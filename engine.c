/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

/* Global supervisor context pointer for signal handlers */
static supervisor_ctx_t *g_ctx = NULL;

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }
    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }
    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;
    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }
        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }
    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "killed";
    case CONTAINER_EXITED:   return "exited";
    default:                 return "unknown";
    }
}

/* ----------------------------------------------------------------
 * Bounded Buffer (producer-consumer, ring buffer)
 * ---------------------------------------------------------------- */

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;
    memset(buffer, 0, sizeof(*buffer));
    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0) return rc;
    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) { pthread_mutex_destroy(&buffer->mutex); return rc; }
    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

/*
 * bounded_buffer_push - Producer inserts a log chunk.
 *
 * Blocks while the buffer is full (classic bounded-buffer pattern).
 * Returns 0 on success, -1 if shutting down.
 *
 * Race condition without mutex: two producer threads could both read
 * the same tail index and write to the same slot, corrupting data.
 * The mutex ensures only one producer modifies tail at a time.
 * not_full prevents writing into a full buffer (lost data).
 * not_empty wakes the consumer after every insert.
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    /* Wait while full and not shutting down */
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    /* Insert at tail */
    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    pthread_cond_signal(&buffer->not_empty);   /* wake consumer */
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * bounded_buffer_pop - Consumer removes a log chunk.
 *
 * Blocks while buffer is empty. Returns 0 on success, -1 on shutdown
 * with nothing left to drain.
 *
 * Race condition without mutex: consumer could read a slot the
 * producer hasn't finished writing yet, getting partial data.
 * Condition variable avoids busy-waiting (CPU waste).
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    /* Wait while empty; if shutting down and empty, we are done */
    while (buffer->count == 0) {
        if (buffer->shutting_down) {
            pthread_mutex_unlock(&buffer->mutex);
            return -1;
        }
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
    }

    /* Remove from head */
    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    pthread_cond_signal(&buffer->not_full);    /* wake producer */
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/* ----------------------------------------------------------------
 * Logging consumer thread
 * ---------------------------------------------------------------- */

/*
 * logging_thread - Drains the bounded buffer and writes to log files.
 *
 * Each log chunk carries the container_id so we can open the right
 * file. We keep it simple: open the file in append mode for every
 * chunk (the OS caches the fd lookup; correctness > micro-perf here).
 */
void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;

    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);

        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            perror("logging_thread: open log file");
            continue;
        }
        /* Write the chunk; ignore partial writes for simplicity */
        write(fd, item.data, item.length);
        close(fd);
    }

    fprintf(stderr, "[logger] thread exiting cleanly\n");
    return NULL;
}

/* ----------------------------------------------------------------
 * Producer thread: reads from a pipe fd and pushes into buffer
 * ---------------------------------------------------------------- */

typedef struct {
    int read_fd;                       /* read end of container's pipe */
    char container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *log_buffer;
} producer_args_t;

static void *producer_thread(void *arg)
{
    producer_args_t *pa = (producer_args_t *)arg;
    log_item_t item;
    ssize_t n;

    while ((n = read(pa->read_fd, item.data, LOG_CHUNK_SIZE)) > 0) {
        strncpy(item.container_id, pa->container_id, CONTAINER_ID_LEN - 1);
        item.length = (size_t)n;
        if (bounded_buffer_push(pa->log_buffer, &item) != 0)
            break;  /* shutting down */
    }

    close(pa->read_fd);
    free(pa);
    return NULL;
}

/* ----------------------------------------------------------------
 * Container child entrypoint (runs after clone())
 * ---------------------------------------------------------------- */

/*
 * child_fn - Runs inside the new namespaces.
 *
 * Steps:
 *   1. Redirect stdout/stderr to the log pipe so all output is
 *      captured by the supervisor's producer thread.
 *   2. chroot into rootfs and chdir to /.
 *   3. Mount /proc so tools like ps work inside the container.
 *   4. Apply nice value for scheduler experiments.
 *   5. exec the requested command.
 */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    /* 1. Redirect stdout and stderr into the logging pipe */
    if (cfg->log_write_fd >= 0) {
        dup2(cfg->log_write_fd, STDOUT_FILENO);
        dup2(cfg->log_write_fd, STDERR_FILENO);
        close(cfg->log_write_fd);
    }

    /* 2. chroot into the container's filesystem */
    if (chroot(cfg->rootfs) != 0) {
        perror("child_fn: chroot");
        return 1;
    }
    if (chdir("/") != 0) {
        perror("child_fn: chdir");
        return 1;
    }

    /* 3. Mount /proc (needed for ps, top, /proc/self, etc.) */
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);

    /* 4. Apply nice value (scheduler experiment support) */
    if (cfg->nice_value != 0)
        nice(cfg->nice_value);

    /* 5. Exec the command */
    char *argv[] = { cfg->command, NULL };
    char *envp[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
        "TERM=xterm",
        NULL
    };

    execve(cfg->command, argv, envp);
    perror("child_fn: execve");
    return 1;
}

/* ----------------------------------------------------------------
 * Monitor registration helpers
 * ---------------------------------------------------------------- */

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;
    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;
    return 0;
}

/* ----------------------------------------------------------------
 * Metadata helpers (called with metadata_lock held)
 * ---------------------------------------------------------------- */

static container_record_t *find_container(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t *c = ctx->containers;
    while (c) {
        if (strcmp(c->id, id) == 0) return c;
        c = c->next;
    }
    return NULL;
}

static container_record_t *find_container_by_pid(supervisor_ctx_t *ctx, pid_t pid)
{
    container_record_t *c = ctx->containers;
    while (c) {
        if (c->host_pid == pid) return c;
        c = c->next;
    }
    return NULL;
}

static container_record_t *alloc_container_record(const control_request_t *req)
{
    container_record_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    strncpy(c->id, req->container_id, CONTAINER_ID_LEN - 1);
    c->state = CONTAINER_STARTING;
    c->soft_limit_bytes = req->soft_limit_bytes;
    c->hard_limit_bytes = req->hard_limit_bytes;
    c->started_at = time(NULL);
    snprintf(c->log_path, PATH_MAX, "%s/%s.log", LOG_DIR, c->id);
    return c;
}

/* ----------------------------------------------------------------
 * Launch a container (called from the supervisor event loop)
 * ---------------------------------------------------------------- */

static pid_t launch_container(supervisor_ctx_t *ctx, const control_request_t *req)
{
    int pipefd[2];
    char *stack;
    pid_t pid;

    /* Create pipe: container writes, supervisor reads */
    if (pipe(pipefd) < 0) {
        perror("launch_container: pipe");
        return -1;
    }

    /* Allocate stack for clone() */
    stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("launch_container: malloc");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    /* Build child config */
    child_config_t *cfg = malloc(sizeof(*cfg));
    if (!cfg) {
        free(stack);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    strncpy(cfg->id,      req->container_id, CONTAINER_ID_LEN - 1);
    strncpy(cfg->rootfs,  req->rootfs,        PATH_MAX - 1);
    strncpy(cfg->command, req->command,       CHILD_COMMAND_LEN - 1);
    cfg->nice_value   = req->nice_value;
    cfg->log_write_fd = pipefd[1];   /* child writes here */

    /* clone() into new PID + UTS + mount namespaces */
    int flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;
    pid = clone(child_fn, stack + STACK_SIZE, flags, cfg);

    /* Parent closes the write end; child has its own copy */
    close(pipefd[1]);
    free(stack);

    if (pid < 0) {
        perror("launch_container: clone");
        close(pipefd[0]);
        free(cfg);
        return -1;
    }
    free(cfg);

    /* Start a producer thread to read the pipe and push into log buffer */
    producer_args_t *pa = malloc(sizeof(*pa));
    if (pa) {
        pa->read_fd    = pipefd[0];
        pa->log_buffer = &ctx->log_buffer;
        strncpy(pa->container_id, req->container_id, CONTAINER_ID_LEN - 1);
        pthread_t tid;
        pthread_create(&tid, NULL, producer_thread, pa);
        pthread_detach(tid);   /* fire-and-forget */
    } else {
        close(pipefd[0]);
    }

    /* Register with kernel monitor */
    if (ctx->monitor_fd >= 0)
        register_with_monitor(ctx->monitor_fd, req->container_id, pid,
                              req->soft_limit_bytes, req->hard_limit_bytes);

    fprintf(stderr, "[supervisor] launched container '%s' pid=%d\n",
            req->container_id, pid);
    return pid;
}

/* ----------------------------------------------------------------
 * SIGCHLD handler — reap zombie children
 * ---------------------------------------------------------------- */

static void sigchld_handler(int sig)
{
    (void)sig;
    if (!g_ctx) return;

    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        pthread_mutex_lock(&g_ctx->metadata_lock);
        container_record_t *c = find_container_by_pid(g_ctx, pid);
        if (c) {
            if (WIFSIGNALED(status)) {
                c->state      = (WTERMSIG(status) == SIGKILL)
                                ? CONTAINER_KILLED : CONTAINER_STOPPED;
                c->exit_signal = WTERMSIG(status);
            } else {
                c->state     = CONTAINER_EXITED;
                c->exit_code = WEXITSTATUS(status);
            }
            fprintf(stderr, "[supervisor] container '%s' pid=%d finished (state=%s)\n",
                    c->id, pid, state_to_string(c->state));

            /* Unregister from kernel monitor */
            if (g_ctx->monitor_fd >= 0)
                unregister_from_monitor(g_ctx->monitor_fd, c->id, pid);
        }
        pthread_mutex_unlock(&g_ctx->metadata_lock);
    }
}

static void sigterm_handler(int sig)
{
    (void)sig;
    if (g_ctx) g_ctx->should_stop = 1;
}

/* ----------------------------------------------------------------
 * Supervisor: handle one incoming CLI request
 * ---------------------------------------------------------------- */

static void handle_request(supervisor_ctx_t *ctx, int client_fd,
                            const control_request_t *req)
{
    control_response_t resp;
    memset(&resp, 0, sizeof(resp));

    if (req->kind == CMD_START || req->kind == CMD_RUN) {
        /* Ensure logs directory exists */
        mkdir(LOG_DIR, 0755);

        pthread_mutex_lock(&ctx->metadata_lock);
        if (find_container(ctx, req->container_id)) {
            snprintf(resp.message, sizeof(resp.message),
                     "container '%s' already exists", req->container_id);
            resp.status = -1;
            pthread_mutex_unlock(&ctx->metadata_lock);
        } else {
            container_record_t *rec = alloc_container_record(req);
            if (!rec) {
                snprintf(resp.message, sizeof(resp.message), "out of memory");
                resp.status = -1;
                pthread_mutex_unlock(&ctx->metadata_lock);
            } else {
                /* Insert into list */
                rec->next      = ctx->containers;
                ctx->containers = rec;
                pthread_mutex_unlock(&ctx->metadata_lock);

                pid_t pid = launch_container(ctx, req);
                pthread_mutex_lock(&ctx->metadata_lock);
                if (pid < 0) {
                    rec->state = CONTAINER_STOPPED;
                    snprintf(resp.message, sizeof(resp.message),
                             "failed to launch container '%s'", req->container_id);
                    resp.status = -1;
                } else {
                    rec->host_pid  = pid;
                    rec->state     = CONTAINER_RUNNING;
                    rec->started_at = time(NULL);
                    resp.status    = 0;
                    snprintf(resp.message, sizeof(resp.message),
                             "started '%s' pid=%d", req->container_id, pid);
                }
                pthread_mutex_unlock(&ctx->metadata_lock);

                /* For CMD_RUN: wait for container to finish */
                if (req->kind == CMD_RUN && pid > 0) {
                    int wstatus;
                    waitpid(pid, &wstatus, 0);
                }
            }
        }

    } else if (req->kind == CMD_PS) {
        /* Print all container metadata into response message */
        char buf[CONTROL_MESSAGE_LEN];
        char all[4096];
        all[0] = '\0';
        snprintf(all, sizeof(all),
                 "%-16s %-8s %-10s %-8s %-12s %-12s\n",
                 "ID", "PID", "STATE", "EXIT", "SOFT(MiB)", "HARD(MiB)");

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = ctx->containers;
        while (c) {
            snprintf(buf, sizeof(buf),
                     "%-16s %-8d %-10s %-8d %-12lu %-12lu\n",
                     c->id, c->host_pid, state_to_string(c->state),
                     c->exit_code,
                     c->soft_limit_bytes >> 20,
                     c->hard_limit_bytes >> 20);
            strncat(all, buf, sizeof(all) - strlen(all) - 1);
            c = c->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        /* Send the full table back to the client */
        write(client_fd, all, strlen(all));
        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message), "ok");

    } else if (req->kind == CMD_LOGS) {
        /* Read the log file and stream it back */
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, req->container_id);
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "no log for '%s'", req->container_id);
        } else {
            char chunk[4096];
            ssize_t n;
            while ((n = read(fd, chunk, sizeof(chunk))) > 0)
                write(client_fd, chunk, n);
            close(fd);
            resp.status = 0;
            snprintf(resp.message, sizeof(resp.message), "ok");
        }

    } else if (req->kind == CMD_STOP) {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = find_container(ctx, req->container_id);
        if (!c) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "container '%s' not found", req->container_id);
        } else if (c->state != CONTAINER_RUNNING) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "container '%s' is not running", req->container_id);
        } else {
            kill(c->host_pid, SIGTERM);
            c->state = CONTAINER_STOPPED;
            resp.status = 0;
            snprintf(resp.message, sizeof(resp.message),
                     "sent SIGTERM to '%s' pid=%d", req->container_id, c->host_pid);
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
    }

    /* Send response struct */
    write(client_fd, &resp, sizeof(resp));
}

/* ----------------------------------------------------------------
 * Supervisor main function
 * ---------------------------------------------------------------- */

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd  = -1;
    ctx.monitor_fd = -1;
    g_ctx = &ctx;

    /* Init metadata lock */
    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) { errno = rc; perror("pthread_mutex_init"); return 1; }

    /* Init bounded log buffer */
    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) { errno = rc; perror("bounded_buffer_init"); return 1; }

    /* Ensure log directory exists */
    mkdir(LOG_DIR, 0755);

    /* 1. Open kernel monitor device (optional — works without it) */
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "[supervisor] WARNING: cannot open /dev/container_monitor"
                " (module not loaded?) — continuing without memory monitoring\n");

    /* 2. Create UNIX domain socket for CLI <-> supervisor IPC */
    struct sockaddr_un addr;
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); return 1; }

    unlink(CONTROL_PATH);   /* remove stale socket if any */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(ctx.server_fd, 8) < 0) { perror("listen"); return 1; }

    /* 3. Install signal handlers */
    struct sigaction sa_chld = { .sa_handler = sigchld_handler,
                                 .sa_flags   = SA_RESTART | SA_NOCLDSTOP };
    sigemptyset(&sa_chld.sa_mask);
    sigaction(SIGCHLD, &sa_chld, NULL);

    struct sigaction sa_term = { .sa_handler = sigterm_handler };
    sigemptyset(&sa_term.sa_mask);
    sigaction(SIGINT,  &sa_term, NULL);
    sigaction(SIGTERM, &sa_term, NULL);

    /* 4. Start logger consumer thread */
    rc = pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);
    if (rc != 0) { errno = rc; perror("pthread_create logger"); return 1; }

    fprintf(stderr, "[supervisor] ready. base-rootfs=%s socket=%s\n",
            rootfs, CONTROL_PATH);

    /* 5. Event loop: accept CLI connections */
    while (!ctx.should_stop) {
        /* Use select() so SIGINT/SIGTERM can interrupt accept */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int sel = select(ctx.server_fd + 1, &rfds, NULL, NULL, &tv);

        if (sel < 0) {
            if (errno == EINTR) continue;   /* signal interrupted us */
            perror("select");
            break;
        }
        if (sel == 0) continue;  /* timeout — check should_stop */

        int client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        control_request_t req;
        ssize_t n = read(client_fd, &req, sizeof(req));
        if (n == (ssize_t)sizeof(req))
            handle_request(&ctx, client_fd, &req);

        close(client_fd);
    }

    /* ---- Graceful shutdown ---- */
    fprintf(stderr, "[supervisor] shutting down...\n");

    /* Stop all running containers */
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *c = ctx.containers;
    while (c) {
        if (c->state == CONTAINER_RUNNING) kill(c->host_pid, SIGTERM);
        c = c->next;
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* Give containers a moment, then reap */
    sleep(1);
    while (waitpid(-1, NULL, WNOHANG) > 0) {}

    /* Stop logger thread */
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);

    /* Free container records */
    pthread_mutex_lock(&ctx.metadata_lock);
    c = ctx.containers;
    while (c) {
        container_record_t *next = c->next;
        free(c);
        c = next;
    }
    ctx.containers = NULL;
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* Close fds */
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
    close(ctx.server_fd);
    unlink(CONTROL_PATH);

    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);

    fprintf(stderr, "[supervisor] clean exit.\n");
    return 0;
}

/* ----------------------------------------------------------------
 * CLI client: send a request to the supervisor over UNIX socket
 * ---------------------------------------------------------------- */

static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to supervisor at %s\n"
                "Is the supervisor running? Try: sudo ./engine supervisor ./rootfs\n",
                CONTROL_PATH);
        close(fd);
        return 1;
    }

    /* Send request */
    if (write(fd, req, sizeof(*req)) != (ssize_t)sizeof(*req)) {
        perror("write"); close(fd); return 1;
    }

    /* For PS and LOGS the supervisor streams text before the response struct */
    if (req->kind == CMD_PS || req->kind == CMD_LOGS) {
        char buf[4096];
        ssize_t n;
        /* Read until we can fit a response struct at the end */
        while ((n = read(fd, buf, sizeof(buf))) > (ssize_t)sizeof(resp)) {
            fwrite(buf, 1, n - sizeof(resp), stdout);
        }
    }

    /* Read response */
    if (read(fd, &resp, sizeof(resp)) == (ssize_t)sizeof(resp)) {
        if (resp.status != 0)
            fprintf(stderr, "Error: %s\n", resp.message);
        else
            printf("%s\n", resp.message);
    }

    close(fd);
    return (resp.status == 0) ? 0 : 1;
}

/* ----------------------------------------------------------------
 * CLI command handlers
 * ---------------------------------------------------------------- */

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command>"
                " [--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs)        - 1);
    strncpy(req.command,      argv[4], sizeof(req.command)       - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command>"
                " [--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs)        - 1);
    strncpy(req.command,      argv[4], sizeof(req.command)       - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) { fprintf(stderr, "Usage: %s logs <id>\n", argv[0]); return 1; }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) { fprintf(stderr, "Usage: %s stop <id>\n", argv[0]); return 1; }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

/* ----------------------------------------------------------------
 * main
 * ---------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }
    if (strcmp(argv[1], "start") == 0) return cmd_start(argc, argv);
    if (strcmp(argv[1], "run")   == 0) return cmd_run(argc, argv);
    if (strcmp(argv[1], "ps")    == 0) return cmd_ps();
    if (strcmp(argv[1], "logs")  == 0) return cmd_logs(argc, argv);
    if (strcmp(argv[1], "stop")  == 0) return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
