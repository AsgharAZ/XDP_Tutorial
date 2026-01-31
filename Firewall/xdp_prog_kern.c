/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

//
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../xdp-tutorial/common/xdp_stats_kern_user.h"
#include "../xdp-tutorial/common/xdp_stats_kern.h"

#include <linux/tcp.h>
#include <linux/udp.h>


/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	if (nh->pos + hdrsize > data_end)
		return -1;
		
	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
	{
		struct ipv6hdr *ip6h = nh->pos;

		/* Pointer-arithmetic bounds check; pointer +1 points to after end of
		* thing being pointed to. We will be using this style in the remainder
		* of the tutorial.
		*/
		if (ip6h + 1 > data_end)
			return -1;

		nh->pos = ip6h + 1;
		*ip6hdr = ip6h;

		return ip6h->nexthdr;
	}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;

	if (icmp6h + 1 > data_end)
		return -1;

	nh->pos   = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

//Putting ipv4 compatability.
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;

	if (icmph + 1 > data_end)
		return -1;

	nh->pos  = icmph + 1;
	*icmphdr = icmph;

	return icmph->type;
}

// Ethernet
//  ├── IPv6
//  │    ├── ICMPv6
//  │    ├── TCP
//  │    └── UDP
//  └── IPv4
//       ├── ICMP
//       ├── TCP
//       └── UDP

//parse_udphdr: parse the udp header and return the length of the udp payload
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}


//parse_tcphdr: parse and return the length of the tcp header
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if(len < sizeof(*h))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + len > data_end)
		return -1;

	nh->pos += len;
	*tcphdr = h;

	return len;
}

// FLOW
struct flow_key_v4 {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

//activity tracking, don’t need full TCP FSM
struct flow_state {
    __u64 last_seen_ns;   // bpf_ktime_get_ns()
    __u64 packets;
    __u64 bytes;
    __u8  tcp_state;     // optional but recommended
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct flow_key_v4);
    __type(value, struct flow_state);
} flow_map SEC(".maps");

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6h;

	struct tcphdr *tcph;
	struct udphdr *udph;
	//Default action
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* ---- Ethernet ---- */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		goto out;


	/* ---- IPv6 ---- */
	if (nh_type == bpf_htons(ETH_P_IPV6)){
		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type < 0)
			goto out;

		// if (nh_type != IPPROTO_ICMPV6)
		// 	goto out;

		/* ---- ICMPv6 ---- */
		if (nh_type == IPPROTO_ICMPV6) {
			if (parse_icmp6hdr(&nh, data_end, &icmp6h) < 0)
				goto out;
		}
		else if (nh_type == IPPROTO_TCP) {
			if (parse_tcphdr(&nh, data_end, &tcph) < 0)
				goto out;
			
			//“Drop all new inbound TCP connection attempts to SSH.”

			//“This packet is attempting to initiate a new TCP connection.”
			// Not match with Established connections, server replies, Existing flows.
			// Blocks ; Port scans, Brute-force attempts, Random internet SSH probes. Makes it Immune to SYN flood CPU exhaustion
			//default-deny for new connections

			// Makes it Immune to SYN flood CPU exhaustion
			// Drops new inbound SSH connection attempts early at XDP
			// Reduces exposure to SSH scans and brute-force attempts
			if (tcph->syn && !tcph->ack &&
				//Port 22 = SSH.
				//“Someone is trying to open a new inbound SSH connection.”
    			tcph->dest == bpf_htons(22)) {
    			action = XDP_DROP;
				goto out;
			}
		}

		//UDP
		else if (nh_type == IPPROTO_UDP) {
			if (parse_udphdr(&nh, data_end, &udph) < 0)
				goto out;

			// The following makes sure that only DNS requests or Replies are allowed, rest are dropped to reduce risk of "amplification attacks" (type of ddos attack)
			// Restrict UDP traffic to DNS only (requests + replies)
			// Reduces UDP attack surface
			if (udph->dest != bpf_htons(53) &&
				udph->source != bpf_htons(53)) {
				action = XDP_DROP;
				goto out;
			}

		}
		else {
			goto out;
		}
		action = XDP_PASS;
	}

	// IPV4 ////////////////////////////
	else if (nh_type == bpf_htons(ETH_P_IP)){
		struct iphdr *iph;
		struct icmphdr *icmph;
		struct flow_key_v4 key = {}; //flow ip4

		
		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type < 0)
			goto out;

		// if (nh_type != IPPROTO_ICMP)
		// 	goto out;

		if (nh_type == IPPROTO_ICMP) {
			if (parse_icmphdr(&nh, data_end, &icmph) < 0)
				goto out;
			if (icmph->type == ICMP_ECHO) {
				action = XDP_DROP;
				goto out;
			}
		}
		else if (nh_type == IPPROTO_TCP) {
			if (parse_tcphdr(&nh, data_end, &tcph) < 0)
				goto out;

			if (tcph->syn && !tcph->ack &&
    			tcph->dest == bpf_htons(22)) {
    			action = XDP_DROP;
				goto out;
				}
		}
		else if (nh_type == IPPROTO_UDP) {
			if (parse_udphdr(&nh, data_end, &udph) < 0)
				goto out;

			if (udph->dest != bpf_htons(53) &&
				udph->source != bpf_htons(53)) {
				action = XDP_DROP;
				goto out;
			}
		}
		else {
			goto out;
		}

		// key.src_ip   = iph->saddr;
		// key.dst_ip   = iph->daddr;
		// key.src_port = tcph->source;
		// key.dst_port = tcph->dest;
		// key.proto    = IPPROTO_TCP;
		// if (parse_icmphdr(&nh, data_end, &icmph) < 0)
		// 	goto out;

		/* IPv4 logic here */
		action = XDP_PASS;
	}
	else {
	// Non IP traffic
		action = XDP_PASS;
		goto out;
	}

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
