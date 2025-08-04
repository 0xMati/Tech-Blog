# Monitoring Windows Server Performance: Essential Counters  
🗓️ Published: 2025-08-04  

## Introduction

Welcome! Monitoring Windows Server performance means tracking key system metrics to catch issues before they cause downtime or slowdowns.  
This guide covers the essential counters for CPU, memory, disk, and network that reveal how your server is really doing.  

Just the basics you need to keep your systems healthy and performant.

The performance counters below focus on basic OS monitoring. Alert thresholds are guidelines and should be adjusted based on server roles and infrastructure sizing to reduce false positives—establishing a baseline per machine is key.

---

## CPU (Processor) Monitoring

Your CPU executes tasks in two main modes:

- **Privileged Mode (Kernel Mode):**  
  This is where the core operating system and drivers run. Code here has full access to hardware and memory. For example, on file servers and print servers, most CPU activity happens in this mode.

- **User Mode:**  
  This is where regular applications run with limited system access. When an application needs to perform a privileged action, like writing a file, it temporarily switches to Kernel Mode.

### What the key CPU counters mean

- `\Processor(*)\% Privileged Time`  
  Percentage of time the CPU spends in Kernel Mode doing system-level work.

- `\Processor(*)\% User Time`  
  Percentage of time spent running applications.

- `\Processor(*)\% Processor Time`  
  Total CPU usage — sum of Privileged and User times.

Note: `Processor(*)` means the combined or individual CPU cores.

If you have issues, you can analyze per-process CPU usage with:  
`\Process(*)\% Processor Time` and `\Process(*)\% Privileged Time`.

### Main CPU counters and alert thresholds

| Counter                              | Normal       | Warning       | Critical        |
|------------------------------------|--------------|---------------|-----------------|
| `\Processor(*)\% Processor Time`   | Less than 50%| 50–80%        | More than 80%   |
| (Sum of % Privileged Time and % User Time) |              |               |                 |
| `\Processor(*)\% Privileged Time`  | Less than 30%| 30–50%        | More than 50%   |
| (CPU time allocated to Kernel)      |              |               |                 |

### Secondary CPU counters and thresholds

| Counter                              | Normal            | Warning                           | Critical                          |
|------------------------------------|-------------------|---------------------------------|----------------------------------|
| `\Processor(*)\% Interrupt Time`   | Less than 10%     | 10–20%                          | More than 20%                    |
| `\Processor(*)\% DPC Time`          | Less than 10%     | 10–20%                          | More than 20%                    |
| `\System\Context Switches/sec`      | Less than 5,000   | More than 2,500 × Number of CPUs | More than 5,000 × Number of CPUs or > 20,000 |

Example: With 4 CPU cores, a warning for context switches would be over 10,000 per second.

### Explanation of secondary counters

- **`% Interrupt Time`:**  
  Measures how much CPU time is spent issuing and scheduling I/O requests from hardware devices such as disks and network cards. This does *not* include the time to actually complete those operations.

- **DPC (Deferred Procedure Calls) Time:**  
  Time the CPU spends processing hardware interrupts. DPCs handle the bulk of interrupt processing work.

- Ideally, your system should spend very little time handling hardware interrupts.

- If `% Privileged Time` goes above 20% on any CPU core *and* either `% DPC Time` or `% Interrupt Time` also exceed 20% on the same core, this is a sign to check for hardware or driver issues.

- **`Context Switches/sec`:**  
  Counts how often the CPU switches from running one thread to another. High values can result from many active threads or heavy disk and network I/O.

- The raw value should be divided by the number of CPUs or cores for a per-core perspective.

- For example, disk contention can cause the CPU to switch tasks frequently while waiting for data.

### Tips to improve CPU efficiency

- Reduce the number of active threads at any one time.

- Increase the **quantum**, which is how many clock cycles a thread can run before the CPU switches to another thread.

- In Windows, you can adjust this by enabling **“Adjust for best performance of background services”**. This lets threads run longer, reducing the number of context switches and improving performance.

---

## Memory Monitoring

Memory is a critical resource your server relies on to run applications and the operating system smoothly. Understanding memory usage helps avoid slowdowns caused by running out of RAM or excessive paging.

### Key concepts

- Each process has its own virtual memory space, but the operating system manages the actual physical RAM and paging file (disk space used as “overflow” RAM).

- **Committed memory** is the total amount of virtual memory reserved for use by all processes. This is the memory Windows has promised to provide, not necessarily the physical RAM allocated at any moment. If committed memory exceeds physical RAM, the system starts using the paging file, which is slower.

- The CPU and drivers use two important memory pools:  
  - **Paged Pool:** memory that can be moved to disk if needed.  
  - **Nonpaged Pool:** memory that must stay in physical RAM.

- The size of these pools depends on your system and Windows version.

### Main memory counters and alert thresholds

| Counter                              | Normal                 | Warning               | Critical               |
|------------------------------------|------------------------|-----------------------|------------------------|
| `\Memory\Free System Page Table Entries` | More than 12,000       | 8,000 to 12,000       | Less than 8,000        |
| `\Memory\Pool Paged Bytes`          | 0–50% of max           | 60–80% of max         | 80–100% of max         |
| `\Memory\Pool Nonpaged Bytes`       | 0–50% of max           | 60–80% of max         | 80–100% of max         |
| `\Memory\Available MBytes`          | More than 10% of total RAM | Less than 5% of total RAM | Less than 1% of total RAM |
| `\Memory\% Committed Bytes In Use`  | Less than 50%          | 60–80%                | More than 80%          |

### What these counters tell you

- **Free System Page Table Entries (PTEs)**  
  These track the number of free memory mappings available to translate virtual addresses to physical memory. If this number drops too low, your system can become unstable.

- **Paged and Nonpaged Pools**  
  These represent kernel memory areas. If either is close to max, it may signal a leak or overuse by drivers or system services.

- **Available MBytes**  
  The amount of free RAM immediately available for use by applications and the system.

- **% Committed Bytes In Use**  
  Shows how much virtual memory (RAM plus page file) is currently in use. High values indicate memory pressure and possible paging.

### When to worry

- Low values of free PTEs or available memory can cause slowdowns or system instability.

- High usage of paged or nonpaged pools suggests resource leaks or misbehaving drivers.

- If `% Committed Bytes In Use` is high, your system may start paging to disk, impacting performance.

### Tips to keep memory healthy

- Monitor these counters regularly to spot trends.

- Investigate and fix any memory leaks in drivers or applications.

- Ensure your system has enough physical RAM for your workload.

- Optimize applications to use memory efficiently.

---

## Disk Monitoring

Disks are often the bottleneck in server performance, so monitoring their health and responsiveness is crucial.

### Main disk counters and alert thresholds

| Counter                          | Normal          | Warning          | Critical         |
|---------------------------------|-----------------|------------------|------------------|
| `\LogicalDisk(*)\Avg. Disk sec/Read`   | Less than 15 ms | More than 15 ms  | More than 25 ms  |
| `\LogicalDisk(*)\Avg. Disk sec/Write`  | Less than 15 ms | More than 15 ms  | More than 25 ms  |
| `\PhysicalDisk(*)\Avg. Disk sec/Read`  | Less than 15 ms | More than 15 ms  | More than 25 ms  |
| `\PhysicalDisk(*)\Avg. Disk sec/Write` | Less than 15 ms | More than 15 ms  | More than 25 ms  |
| `\LogicalDisk(*)\% Free Space`          | More than 10%   | Less than 10%    | Less than 5%     |

### What these counters mean

- **Avg. Disk sec/Read** and **Avg. Disk sec/Write** measure the average time it takes to read from or write to the disk. Lower times are better, as they mean faster response.

- Typical warning thresholds start at 15 milliseconds; if reads or writes take longer, it may indicate disk congestion or hardware issues.

- **% Free Space** indicates how much free space is left on each logical disk. Running out of space can cause performance problems and should be monitored carefully.

### Other useful counters

- **Disk Queue Length:**  
  The number of disk I/O operations waiting to be processed. A high queue length suggests the disk subsystem is overloaded.

- Disk counters come in two types:  
  - **PhysicalDisk:** monitors individual physical disks or disk arrays.  
  - **LogicalDisk:** monitors volumes or partitions assigned drive letters (like C:, D:, etc.).

### What to do if you see issues

- If disk read or write times are high, check for hardware faults, driver problems, or excessive fragmentation.

- Consider upgrading storage hardware or optimizing caching strategies if disk performance is consistently poor.

- Keep at least 10% free space on disks to maintain good performance and allow system processes room to work.

---

## Network Monitoring

Monitoring network performance helps ensure your server can send and receive data smoothly without bottlenecks.

### Main network counters and alert thresholds

| Counter                                 | Normal          | Warning          | Critical         |
|----------------------------------------|-----------------|------------------|------------------|
| `\Network Interface(*)\Current Bandwidth (bits/sec)` | Varies (depends on interface speed) | — | — |
| `% Network utilization (outbound)`     | Less than 30%   | 30–60%           | More than 60%    |
| `% Network utilization (inbound)`      | Less than 30%   | 30–60%           | More than 60%    |
| `\Network Interface(*)\Output Queue Length` | 0           | 1–2              | More than 2      |

### What these counters mean

- **Current Bandwidth** reflects the maximum speed of the network interface. Note that if you use teaming (combining interfaces), this value may be higher than expected.

- **Bytes Sent/sec** and **Bytes Received/sec** (not shown here) help calculate network utilization percentage for outbound and inbound traffic.

- High utilization percentages (above 60%) may indicate network saturation.

- **Output Queue Length** measures the number of packets waiting to be sent. A queue length above 2 could mean congestion or network issues.

### Other useful counters

- **TCP Connections Established:**  
  The number of active TCP connections on the server. If this number is consistently very high (e.g., above 3,000), it could signal network overload or potential security issues.

- **TCP Connections Active:**  
  Counts the number of TCP connections initiated by the server over time.

### What to do if you see issues

- Check for network saturation if utilization is high.

- Investigate high output queue lengths for possible device or driver problems.

- Monitor TCP connections to detect unusual activity or connection leaks.

---

## Conclusion

Keeping an eye on these essential performance counters—CPU, memory, disk, and network—gives you a solid grip on your Windows Server’s health.  
Regular monitoring helps catch issues early, optimize performance, and keep your systems running smoothly without nasty surprises.  

Remember, these are starting points. Adapt thresholds to your specific workloads and hardware, and always build baselines to understand what “normal” looks like for your servers.  

Happy monitoring!
