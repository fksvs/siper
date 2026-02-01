# Siper (Shield)

Siper is a high-performance, XDP-based IP blacklist firewall built with Go and C (eBPF). It allows you to drop malicious traffic at the earliest possible stage in the Linux networking stack—the network driver level. By leveraging XDP (Express Data Path), Siper processes packets before they even reach the kernel's heavy networking subsystem, providing extreme performance even under heavy DDoS conditions.

## Features

- **XDP-Powered Performance**: Packet filtering happens at the NIC driver level using XDP_DROP, resulting in significantly lower CPU overhead compared to iptables or nftables.

- **LPM (Longest Prefix Match)**: Supports CIDR-based blocking (e.g., 192.168.1.0/24) using specialized BPF LPM Trie maps for efficient IP range lookups.

- **Persistent Configuration**: Rules are managed via a local JSON-based blacklist, allowing for easy auditing and versioning of blocked addresses.

- **Real-time Observability**: Built-in metrics to track packet and byte counters for both dropped and passed traffic.

- **Minimalist Architecture**: A compiled BPF object handles the data plane, while a Go-based CLI manages the control plane.

## Architecture

Siper operates on the principle of separating the Control Plane (User-space) from the Data Plane (Kernel-space).

### The Management Flow (User-space)

1. **Rule Definition**: The user adds/removes CIDRs via the CLI. These are stored in a blacklist.json file.
2. **Loading**: When siper run is executed, the Go application parses the JSON, compiles/loads the eBPF object, and populates the BPF Map with the IP prefixes.
3. **Monitoring**: The CLI communicates with the kernel via BPF syscalls to dump metrics and current map states without interrupting traffic.

### The Packet Flow (Kernel-space)

1. **Ingress**: A packet arrives at the network interface.
2. **Lookup**: The XDP program intercepts the packet and performs a lookup in the block_list map.
3. **Verdict**:

    - **Match**: The packet is dropped immediately (XDP_DROP).
    - **No Match**: The packet is passed up to the standard Linux networking stack (XDP_PASS).

## Installation & Usage

**Prerequisites**

- **Linux Kernel**: 5.4 or newer (with XDP support).
- **Go**: 1.21+ installed.
- **Clang/LLVM**: For compiling the eBPF C program into the .o object.
- **Permissions**: Root access or CAP_NET_ADMIN / CAP_BPF capabilities.

### 1.Build the Project

```bash
make
```

Move to `build/` directory

### 2.Manage the Blacklist

Add or remove IP ranges from your local configuration file:

```bash
# Add a CIDR to the list
sudo ./siper add --cidr 1.2.3.0/24 --comment "Known botnet"

# Delete a rule
sudo ./siper del --cidr 1.2.3.0/24
```

### 3.Running the Firewall

Attach the firewall to a specific network interface:

```bash
# Start the firewall
sudo ./siper run --iface eth0 --path ./blacklist.json

# Stop and detach the firewall
sudo ./siper stop --iface eth0
```

### 4.Monitoring Metrics and Keys

View what is happening inside the kernel:

```bash
# See currently active keys in the BPF map
sudo ./siper dump-keys

# Monitor drop/pass statistics
sudo ./siper dump-metrics
```

## Contributing

Pull requests are welcome. For bug fixes and small improvements, please submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is free software; you can redistribute it and/or modify it under the terms of the GPLv3 license. See LICENSE for details.