# OS-Jackfruit — Supervised Multi-Container Runtime

## 1. Team Information

| Name | SRN |
|------|-----|
| J Naga Vamsi | PES1UG24CS201 |
| K Pranay Krishna | PES1UG24CS242 |

---

## 2. Build, Load, and Run Instructions

### Prerequisites
- Ubuntu 22.04 or 24.04 in a VM (Secure Boot OFF, no WSL)
- `sudo apt install -y build-essential linux-headers-$(uname -r)`

### Download Alpine rootfs
```bash
mkdir rootfs
wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.20.3-x86_64.tar.gz -C rootfs
```

### Build everything
```bash
make
```
This builds: `engine`, `memory_hog`, `cpu_hog`, `io_pulse`, and `monitor.ko`.

### Load kernel module
```bash
sudo insmod monitor.ko
# Allow dmesg access
sudo sysctl kernel.dmesg_restrict=0
# Verify device created
ls -la /dev/container_monitor
```

### Start supervisor (Terminal 1)
```bash
sudo ./engine supervisor ./rootfs
```

### Container operations (Terminal 2)
```bash
# Start a container in background
sudo ./engine start alpha ./rootfs /bin/sh

# Start a container and wait for it
sudo ./engine run test1 ./rootfs /bin/hostname

# List all containers
sudo ./engine ps

# View container logs
sudo ./engine logs alpha

# Stop a container
sudo ./engine stop alpha
```

### Run memory limit test
```bash
sudo cp memory_hog ./rootfs/
sudo ./engine start memtest ./rootfs /memory_hog --soft-mib 5 --hard-mib 10
dmesg | grep container_monitor
```

### Run scheduler experiments
```bash
sudo cp cpu_hog ./rootfs/
sudo cp io_pulse ./rootfs/

# Experiment 1: Different priorities
sudo ./engine start cpu_hi ./rootfs /cpu_hog --nice 0
sudo ./engine start cpu_lo ./rootfs /cpu_hog --nice 19
sleep 12
cat logs/cpu_hi.log
cat logs/cpu_lo.log

# Experiment 2: CPU-bound vs I/O-bound
sudo ./engine start cpu_w ./rootfs /cpu_hog --nice 0
sudo ./engine start io_w  ./rootfs /io_pulse --nice 0
sleep 12
cat logs/cpu_w.log
cat logs/io_w.log
```

### Clean shutdown
```bash
# Ctrl+C on supervisor terminal, then:
sudo rmmod monitor
dmesg | grep container_monitor | tail -5
```

---

## 3. Demo Screenshots

**Screenshot 1 — Two containers running under one supervisor**
![ss1](screenshots/ss1.png)

**Screenshot 2 — ps output showing container metadata**
![ss2](screenshots/ss2.png)

**Screenshot 3 — Logging pipeline proof**
![ss3](screenshots/ss3.png)

**Screenshot 4 — CLI command and supervisor response**
![ss4](screenshots/ss4.png)

**Screenshot 5 — Soft limit warning in dmesg**
![ss5](screenshots/ss5.png)

**Screenshot 6 — Hard limit kill in dmesg**
![ss6](screenshots/ss6.png)

**Screenshot 7 — Scheduler experiment results**
![ss7](screenshots/ss7.png)

**Screenshot 8 — Clean teardown, no zombies**
![ss8](screenshots/ss8.png)

## 4. Engineering Analysis

### 4.1 Isolation Mechanisms

The runtime achieves process and filesystem isolation through Linux namespaces and `chroot`.

**Namespaces** are created using `clone()` with three flags:
- `CLONE_NEWPID` — gives the container a private PID namespace. The first process inside sees itself as PID 1. The host kernel still tracks the real PID (e.g. 27496), but the container cannot see or signal host processes.
- `CLONE_NEWUTS` — gives the container its own hostname. Changing the hostname inside the container does not affect the host.
- `CLONE_NEWNS` — gives the container a private mount namespace. Mounts inside (like `/proc`) are invisible to the host.

**`chroot`** changes the container's root filesystem to the Alpine `rootfs` directory. The container can only access files inside that tree. The host filesystem is not visible.

**What the host kernel still shares:** All containers share the same kernel. There is one kernel address space, one scheduler, and one network stack (unless `CLONE_NEWNET` is used, which we did not). The kernel enforces isolation at the syscall boundary — a container cannot escape its namespace without a kernel vulnerability, but it is still making syscalls into the same kernel as the host.

### 4.2 Supervisor and Process Lifecycle

A long-running supervisor is necessary because containers are child processes. Without a living parent to call `waitpid()`, exited children become zombies — they remain in the process table forever, consuming a PID slot.

**Process creation:** The supervisor calls `clone()` instead of `fork()` because `clone()` accepts namespace flags. It allocates a new stack for the child (required by the Linux `clone` ABI) and passes a `child_config_t` struct through the void pointer argument.

**Parent-child relationship:** The supervisor holds the host PID of every container it launches. When a container exits, the kernel sends `SIGCHLD` to the supervisor. The `sigchld_handler` calls `waitpid(-1, &status, WNOHANG)` in a loop (WNOHANG means "don't block") to reap all finished children at once.

**Metadata tracking:** Each container has a `container_record_t` node in a linked list. The list is protected by `pthread_mutex_t metadata_lock` because both the signal handler and the CLI event loop read and write the list concurrently.

**Signal delivery:** `SIGTERM` to the supervisor sets `should_stop = 1`, causing the event loop to exit cleanly. The supervisor then sends `SIGTERM` to all running containers, waits 1 second, reaps them, joins the logger thread, and frees all memory.

### 4.3 IPC, Threads, and Synchronization

The project uses two IPC mechanisms:

**1. Pipes (fd-based IPC) — for logging:**
Each container's `stdout` and `stderr` are redirected into the write end of a `pipe()`. The supervisor holds the read end. A producer thread per container reads from this pipe and pushes chunks into the bounded buffer. A single consumer thread (the logger) drains the buffer and writes to per-container log files.

**2. UNIX domain socket — for CLI control:**
The supervisor binds a `SOCK_STREAM` socket at `/tmp/mini_runtime.sock`. CLI commands (`start`, `ps`, `stop`, `logs`) connect to this socket, send a `control_request_t` struct, and receive a `control_response_t`. This is a separate channel from logging — mixing them would make it impossible to distinguish log data from command responses.

**Bounded buffer synchronization:**

The bounded buffer is a ring buffer with capacity 16. It uses:
- `pthread_mutex_t mutex` — mutual exclusion around head/tail/count fields
- `pthread_cond_t not_full` — producer waits here when buffer is full
- `pthread_cond_t not_empty` — consumer waits here when buffer is empty

**Race conditions without synchronization:**
- Two producer threads could read the same `tail` index simultaneously and write to the same slot, corrupting both entries.
- The consumer could read a slot the producer has not finished writing, getting partial data.
- `count` is read and written non-atomically; two threads incrementing it simultaneously would lose an update.

**Why mutex + condition variable over semaphore or spinlock:**
- A spinlock wastes CPU burning in a loop. Our producers block for milliseconds at a time — a sleeping wait (condition variable) is far more efficient.
- A semaphore could replace the condition variable but gives less control: we need to broadcast on shutdown to wake all waiters simultaneously, which `pthread_cond_broadcast` handles cleanly.
- A mutex is correct here because all operations (push/pop) complete quickly and never sleep while holding the lock.

**Container metadata list:**
Protected by a separate `metadata_lock` mutex. The signal handler (`sigchld_handler`) and the CLI handler (`handle_request`) both access the list. Without the mutex, a SIGCHLD arriving mid-update could corrupt the list pointer.

### 4.4 Memory Management and Enforcement

**What RSS measures:** Resident Set Size is the number of physical RAM pages currently mapped into a process's address space. It measures actual memory consumption — pages that are in RAM right now. It does not measure:
- Swapped-out pages (in swap, not RAM)
- Memory-mapped files that are not yet faulted in
- Shared library pages counted once per process even if shared

**Why soft and hard limits are different policies:**
A soft limit is a warning threshold. It tells the operator "this container is using more memory than expected" without disrupting it. This is useful for detecting memory leaks early. A hard limit is an enforcement threshold. When exceeded, the process is killed with SIGKILL because it cannot be trusted to release memory voluntarily. Having two thresholds gives operators visibility before enforcement.

**Why enforcement belongs in kernel space:**
User-space monitoring (e.g. a polling thread in the supervisor) has a fundamental race: between the moment it reads RSS and the moment it sends SIGKILL, the process can allocate gigabytes more. The kernel module runs in kernel context with direct access to `mm_struct`. It can check RSS and send SIGKILL atomically within the same timer callback, with no scheduling gap between check and action. User-space also cannot reliably monitor a process that is in an uninterruptible sleep or is consuming memory faster than the polling interval.

### 4.5 Scheduling Behavior

Linux uses the Completely Fair Scheduler (CFS). CFS assigns each runnable process a virtual runtime (vruntime). The process with the smallest vruntime runs next. `nice` values map to weights: nice=0 has weight 1024, nice=19 has weight 15. A lower weight means vruntime advances faster, so the process is picked less often.

**Experiment 1 results — different nice values:**

| Container | Nice | Final Accumulator |
|-----------|------|-------------------|
| cpu_hi2   | 0    | 12,661,912,905,114,267,237 |
| cpu_lo2   | 19   | 4,008,391,960,072,671,380  |

cpu_hi2 completed approximately **3x more work** in the same 10 seconds. This matches the CFS weight ratio: weight(0)/weight(19) = 1024/15 ≈ 68. In practice the ratio is lower because other system processes also share the CPU, but the directional result is clear — higher nice value = less CPU share.

**Experiment 2 results — CPU-bound vs I/O-bound:**

| Container | Type      | Behavior |
|-----------|-----------|----------|
| cpu_w     | CPU-bound | Printed accumulator every second for 10s, consumed ~100% CPU |
| io_w      | I/O-bound | Completed 20 iterations with 200ms sleep between each |

The I/O-bound process voluntarily blocked on `usleep()` and `fsync()` between iterations. CFS immediately descheduled it during sleep and gave the full CPU to cpu_w. When io_w woke up, it briefly preempted cpu_w to write its next chunk, then went back to sleep. This demonstrates that I/O-bound processes do not compete fairly with CPU-bound ones under CFS — they yield the CPU willingly, which is why interactive workloads remain responsive even when a CPU hog is running.

---

## 5. Design Decisions and Tradeoffs

### Namespace Isolation
**Choice:** PID + UTS + mount namespaces via `clone()`, `chroot` for filesystem isolation.
**Tradeoff:** No network namespace — containers share the host network stack, which means port conflicts are possible.
**Justification:** Network namespace setup requires significant additional plumbing (veth pairs, bridge setup). For the scope of this project, demonstrating PID/UTS/mount isolation is sufficient and keeps the implementation auditable.

### Supervisor Architecture
**Choice:** Single long-running supervisor process with a UNIX socket event loop.
**Tradeoff:** The event loop is single-threaded, so a slow CLI command (e.g. streaming a large log) blocks other commands briefly.
**Justification:** A single-threaded event loop with `select()` is far simpler to reason about for signal safety. Multi-threaded accept loops require careful signal masking. For a course project, correctness over throughput is the right call.

### IPC and Logging
**Choice:** Pipe for log data, UNIX domain socket for control.
**Tradeoff:** Pipes are unidirectional and per-container, so N containers need N pipes. A shared memory ring buffer would be more efficient.
**Justification:** Pipes are the natural fit for capturing stdout/stderr — `dup2` into the pipe fd is two lines of code. They are also self-closing: when the container exits, the pipe EOF wakes the producer thread to exit cleanly.

### Kernel Monitor
**Choice:** Mutex to protect the monitored list; `mutex_trylock` in the timer callback.
**Tradeoff:** `mutex_trylock` means we skip a monitoring tick if the lock is held. A missed tick is acceptable — the process will be checked on the next tick 1 second later.
**Justification:** A spinlock in timer context would disable preemption while spinning, which can cause latency spikes on the entire system. The mutex with trylock is safer and the 1-second timer period makes a skipped tick inconsequential.

### Scheduler Experiments
**Choice:** Measure accumulated work (accumulator value) as the metric, not wall-clock time.
**Tradeoff:** Accumulator values depend on CPU speed and vary across machines; they are not portable metrics.
**Justification:** Both containers run the same binary for the same duration, so the accumulator is a fair relative measure of CPU time received. Absolute values don't matter — the ratio does.

---

## 6. Scheduler Experiment Results

### Experiment 1: CPU-bound vs CPU-bound, different nice values

Both containers ran `/cpu_hog` for 10 seconds simultaneously.

| Container | Nice value | CFS weight | Final accumulator |
|-----------|-----------|------------|-------------------|
| cpu_hi2   | 0         | 1024       | 12,661,912,905,114,267,237 |
| cpu_lo2   | 19        | 15         | 4,008,391,960,072,671,380  |

**Ratio:** cpu_hi2 / cpu_lo2 ≈ 3.16x

**Analysis:** Linux CFS gave cpu_hi2 more CPU time proportional to its higher weight. The theoretical weight ratio is 1024/15 ≈ 68x, but the observed ratio is only ~3x because other processes (gnome-shell, Firefox) on the 4-core VM also competed for CPU, diluting the difference. The directional result confirms CFS fairness: higher priority = more CPU share.

### Experiment 2: CPU-bound vs I/O-bound, same nice value

Both containers ran at nice=0 simultaneously.

| Container | Type      | Duration | CPU behavior |
|-----------|-----------|----------|--------------|
| cpu_w     | CPU-bound | 10s      | Continuous computation, reported every second |
| io_w      | I/O-bound | ~4s      | 20 iterations × 200ms sleep = voluntarily yielded CPU |

**Analysis:** The I/O-bound process completed all 20 iterations and exited in about 4 seconds despite running alongside a CPU hog. This is because `usleep()` and `fsync()` cause the process to block, removing it from the CFS run queue entirely. CFS only competes among runnable processes — a sleeping process does not accumulate vruntime debt. When io_w woke up, it had a smaller vruntime than cpu_w and was immediately scheduled. This demonstrates the key CFS property: I/O-bound processes are naturally responsive because they spend most of their time sleeping, not running.
