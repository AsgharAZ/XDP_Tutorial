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

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

//the VLAN tag header is not exported by any of the IP header files.
// struct vlan_hdr {
// 	__be16	h_vlan_TCI;
// 	__be16	h_vlan_encapsulated_proto;
// };

// static __always_inline int proto_is_vlan(__u16 h_proto)
// {
// 	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
// 		  h_proto == bpf_htons(ETH_P_8021AD));
// }
/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in network byte order.
 */


static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	//assignment 4 addition
	// struct vlan_hdr *vlh;
	// __u16 h_proto;
	// int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */

	// This was the one that was given previously, moving the pointer by 1 byte is not enough.
	// if (nh->pos + 1 > data_end)
	// 	return -1;

	if (nh->pos + hdrsize > data_end)
		return -1;
		
	nh->pos += hdrsize;
	*ethhdr = eth;

	//ass4
	// vlh = nh->pos;
	// h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	// #pragma unroll
	// for (i = 0; i < VLAN_MAX_DEPTH; i++) {
	// 	if (!proto_is_vlan(h_proto))
	// 		break;

	// 	if (vlh + 1 > data_end)
	// 		break;

	// 	h_proto = vlh->h_vlan_encapsulated_proto;
	// 	if (vlans) /* collect VLAN ids */
	// 		vlans->id[i] =
	// 			(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

	// 	vlh++;
	// }

	// nh->pos = vlh;

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

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6h;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	// nh_type = parse_ethhdr(&nh, data_end, &eth);
	// if (nh_type != bpf_htons(ETH_P_IPV6))
	// 	goto out;


	/* ---- Ethernet ---- */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		goto out;

	// Adding the functionality of ipv4
	// if (nh_type != bpf_htons(ETH_P_IPV6))
	// 	goto out;

	/* ---- IPv6 ---- */
	if (nh_type == bpf_htons(ETH_P_IPV6)){
		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type < 0)
			goto out;

		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		/* ---- ICMPv6 ---- */
		if (parse_icmp6hdr(&nh, data_end, &icmp6h) < 0)
			goto out;
		action = XDP_PASS;
	}

	else if (nh_type == bpf_htons(ETH_P_IP)){
		/* IPv4 path */
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type < 0)
			goto out;

		if (nh_type != IPPROTO_ICMP)
			goto out;

		if (parse_icmphdr(&nh, data_end, &icmph) < 0)
			goto out;

		/* IPv4 logic here */
		action = XDP_PASS;
	}
	else {
	// Non IP traffic
		action = XDP_PASS;
		goto out;
	}

	
    /* Only acts on echo requests */
    // if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST) { //ensure this is echo request
	// 	 /* Convert sequence number from network to host order, only if needed if it detects in compilation time */
    //     __u16 seq = bpf_ntohs(icmp6h->icmp6_sequence); //extract sequence number

    //     if ((seq % 2) == 0)
    //         action = XDP_DROP;
    //     else
    //         action = XDP_PASS;

    //     goto out;
    // }
	// action = XDP_DROP;

	// comment this out if you wanna do the decomment above thing
	// action = XDP_PASS;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
