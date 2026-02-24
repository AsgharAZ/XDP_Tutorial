# XDP Firewall with Flow Management

This is a high-performance firewall implementation using eXpress Data Path (XDP) with comprehensive flow tracking and management.

## Overview

The firewall consists of two main components:

1. **Kernel-side XDP program** (`xdp_prog_kern.c`) - Processes packets at the earliest possible point in the network stack
2. **User-space flow manager** (`flow_manager.c`) - Manages flow expiration, logging, and cleanup

## Features

### Packet Processing
- **IPv4 and IPv6 support** with full protocol parsing
- **TCP, UDP, and ICMP filtering** with protocol-specific rules
- **5-tuple flow tracking** (source IP, destination IP, source port, destination port, protocol)
- **Bidirectional flow management** (tracks both forward and reverse flows)

### Firewall Rules
- **SSH protection** - Blocks new inbound SSH connection attempts (port 22)
- **DNS restriction** - Only allows UDP traffic on port 53 (DNS)
- **ICMP filtering** - Blocks ICMP echo requests (ping)
- **Stateful filtering** - Only allows new connections via SYN packets

### Flow Management
- **Configurable timeouts**:
  - TCP flows: 2 minutes
  - UDP flows: 30 seconds  
  - ICMP flows: 10 seconds
- **Automatic flow expiration** based on inactivity
- **Flow logging** to `flow_log.txt` with detailed information
- **Memory cleanup** - expired flows are removed from kernel maps

## Architecture

```
Network Interface → XDP Program → Flow Tracking → Firewall Rules → Action
                                      ↓
                              User-space Manager
                                      ↓
                              Flow Expiration & Logging
```

### Flow Key Structure
```c
struct flow_key_v4 {
    __u32 src_ip;      // Source IP address
    __u32 dst_ip;      // Destination IP address  
    __u16 src_port;    // Source port
    __u16 dst_port;    // Destination port
    __u8  proto;       // Protocol (TCP/UDP/ICMP)
};
```

### Flow State Tracking
```c
struct flow_state {
    __u64 last_seen_ns;  // Last activity timestamp
    __u64 packets;       // Packet count
    __u64 bytes;         // Byte count
    __u8  tcp_state;     // TCP state (optional)
};
```

## Building

### Prerequisites
- Linux kernel with XDP support
- LLVM and Clang for BPF compilation
- libbpf development libraries

### Build Commands
```bash
# Build both kernel and user-space components
make

# Clean build artifacts
make clean
```

### Build Dependencies
The Makefile automatically handles:
- BPF object compilation (`xdp_prog_kern.o`)
- User-space binary compilation (`flow_manager`)
- libbpf library linking

## Usage

### 1. Load XDP Program
```bash
# Attach XDP program to network interface (requires root)
sudo ip link set dev <interface> xdp obj xdp_prog_kern.o sec xdp
```

### 2. Start Flow Manager
```bash
# Run flow manager to monitor and clean expired flows
sudo ./flow_manager
```

### 3. Monitor Flow Logs
```bash
# View flow expiration logs
tail -f flow_log.txt
```

### 4. Remove XDP Program
```bash
# Detach XDP program from interface
sudo ip link set dev <interface> xdp off
```

## Flow Log Format

The flow manager writes expired flows to `flow_log.txt` with the following format:

```
[2026-02-11 19:30:15] TCP 192.168.1.100:54321 -> 10.0.0.50:80 | Packets: 150 | Bytes: 45000 | Reason: TIMEOUT
[2026-02-11 19:30:16] UDP 192.168.1.101:12345 -> 8.8.8.8:53 | Packets: 2 | Bytes: 120 | Reason: TIMEOUT
```

Fields:
- **Timestamp**: When the flow was expired
- **Protocol**: TCP, UDP, or ICMP
- **Source**: IP and port of the source
- **Destination**: IP and port of the destination  
- **Packets**: Total packets in the flow
- **Bytes**: Total bytes in the flow
- **Reason**: Why the flow was expired (currently only "TIMEOUT")

## Performance Characteristics

### XDP Advantages
- **Zero-copy processing** - packets processed in-place
- **Early packet drop** - malicious traffic dropped before kernel processing
- **BPF JIT compilation** - near-native performance
- **CPU efficiency** - minimal overhead per packet

### Flow Management
- **Efficient iteration** - only processes active flows
- **Configurable timeouts** - balance between memory usage and connection tracking
- **Atomic operations** - safe concurrent access to flow maps

## Security Features

### Protection Against Attacks
- **SYN flood protection** - drops new SSH connection attempts
- **DNS amplification prevention** - restricts UDP to DNS only
- **ICMP flood mitigation** - blocks ping requests
- **Stateful filtering** - prevents connection bypass

### Flow Tracking Security
- **Bidirectional tracking** - prevents flow spoofing
- **Activity-based expiration** - closes idle connections
- **Memory management** - prevents flow table exhaustion

## Configuration

### Timeout Configuration
Edit `flow_manager.c` to adjust flow timeouts:

```c
#define TCP_TIMEOUT_MS    120000  /* 2 minutes for TCP */
#define UDP_TIMEOUT_MS    30000   /* 30 seconds for UDP */
#define ICMP_TIMEOUT_MS   10000   /* 10 seconds for ICMP */
```

### Firewall Rules
Edit `xdp_prog_kern.c` to modify firewall rules:

- SSH blocking: Lines 210-216
- DNS restriction: Lines 226-233
- ICMP filtering: Lines 258-262

## Troubleshooting

### Common Issues

1. **Permission denied**
   ```bash
   # XDP operations require root privileges
   sudo make
   sudo ./flow_manager
   ```

2. **Missing dependencies**
   ```bash
   # Install required packages (Ubuntu/Debian)
   sudo apt install clang llvm libbpf-dev
   ```

3. **Interface not found**
   ```bash
   # List available interfaces
   ip link show
   
   # Use correct interface name
   sudo ip link set dev eth0 xdp obj xdp_prog_kern.o sec xdp
   ```

### Debugging

1. **Check XDP attachment**
   ```bash
   ip link show <interface>
   # Look for "xdp" in the output
   ```

2. **Monitor flow activity**
   ```bash
   # Watch flow log in real-time
   tail -f flow_log.txt
   ```

3. **Check system resources**
   ```bash
   # Monitor memory usage
   free -h
   
   # Check for dropped packets
   cat /proc/net/dev
   ```

## Development

### Adding New Protocols
1. Add protocol parsing in `xdp_prog_kern.c`
2. Update flow key structure if needed
3. Add timeout configuration in `flow_manager.c`
4. Update logging format as required

### Performance Tuning
1. Adjust flow timeouts based on traffic patterns
2. Monitor memory usage with large flow tables
3. Consider flow table size limits for high-traffic scenarios

## License

This project is licensed under the GPL-2.0 License - see the LICENSE file for details.