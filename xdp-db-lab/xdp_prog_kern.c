// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

/* Simple counter map: key = protocol, value = packet count */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u8);     // protocol number
    __type(value, __u64);  // packet counter
} proto_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 proto = ip->protocol;

    __u64 *value = bpf_map_lookup_elem(&proto_map, &proto);

    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&proto_map, &proto, &init_val, BPF_ANY);
    }

    return XDP_PASS;
}