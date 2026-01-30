# XDP Tutorial / Flow-Based Firewall

This repository is a learning and experimentation project based on the
[xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial).

The goal is to build a **basic flow-tracking firewall using XDP/eBPF** that
processes packets at the earliest point in the Linux networking stack.

The project focuses on:
- Parsing Ethernet, IP, and L4 headers in XDP
- Identifying flows using the 5-tuple (src/dst IP, ports, protocol)
- Maintaining per-flow state and statistics using BPF maps
- Applying idle timeouts to decide when a flow is considered closed
- Using a user-space program to read expired flows, write them to a file,
  and clean them up from the kernel map

This is not a production firewall. The emphasis is on understanding XDP,
packet parsing, flow lifecycle management, and kernel ↔ user-space
interaction.

VLAN handling and advanced protocol support are intentionally kept out for
now and may be added later.
