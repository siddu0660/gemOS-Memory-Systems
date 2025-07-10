## gemOS v2p.c

This project implements **virtual memory management** for the gemOS operating system. It covers:

- **Address Space Management:** Handles creation, merging, and protection of memory regions using system calls similar to `mmap`, `munmap`, and `mprotect`.
- **Page Table Manipulation & Lazy Allocation:** Allocates physical memory only on first access, manages page faults, and updates page tables to enforce permissions.

The implementation focuses on efficient memory usage, correct permission enforcement, and robust handling of memory operations within a process's address space.
