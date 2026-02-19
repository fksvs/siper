#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

// structure to hold IP address and prefix in CIDR form
struct ipv4_lpm_key {
	__u32 prefixlen;
	__u32 data;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ipv4_lpm_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 65535);
} ipv4_lpm_map SEC(".maps");

// structure to count packets and total bytes
struct datarec {
	__u64 packets;
	__u64 bytes;
};

#define METRICS_PASS 0
#define METRICS_DROP 1

// eBPF maps to hold metrics
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, 2);
} metrics_map SEC(".maps");

struct hdr_cursor {
	void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
					struct ethhdr **eth_hdr)
{
	struct ethhdr *eth = nh->pos;

	if ((void *)(eth + 1) > data_end) {
		return -1;
	}

	// set pos to the next header
	nh->pos = eth + 1;
	*eth_hdr = eth;

	return eth->h_proto;
}

static __always_inline int parse_ipv4(struct hdr_cursor *nh, void *data_end,
				      struct iphdr **ip_hdr)
{
	struct iphdr *iph = nh->pos;

	if ((void *)(iph + 1) > data_end) {
		return -1;
	}

	__u32 ihl_bytes = iph->ihl * 4;
	if (ihl_bytes < sizeof(*iph)) {
		return -1;
	}
	if ((void *)iph + ihl_bytes > data_end) {
		return -1;
	}

	nh->pos = (void *)iph + ihl_bytes;
	*ip_hdr = iph;
	return iph->protocol;
}

static __always_inline void metrics_inc(__u32 key, __u64 bytes)
{
	struct datarec *rec = bpf_map_lookup_elem(&metrics_map, &key);

	if (rec) {
		rec->packets++;
		rec->bytes += bytes;
	}
}

static __always_inline int *map_lookup(__u32 ipaddr)
{
	struct ipv4_lpm_key key = {
		.prefixlen = 32,
		.data = ipaddr,
	};

	return bpf_map_lookup_elem(&ipv4_lpm_map, &key);
}

SEC("xdp")
int xdp_siper_firewall(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u64 pkt_len = (__u64)(data_end - data);

	struct ethhdr *eth;
	struct iphdr *iph;
	struct hdr_cursor nh;
	nh.pos = data;

	int eth_proto_be = parse_ethhdr(&nh, data_end, &eth);
	if (eth_proto_be < 0) {
		metrics_inc(METRICS_PASS, pkt_len);
		return XDP_PASS;
	}

	__u16 eth_proto = bpf_ntohs((__be16)eth_proto_be);
	if (eth_proto != ETH_P_IP) {
		metrics_inc(METRICS_PASS, pkt_len);
		return XDP_PASS;
	}

	if (parse_ipv4(&nh, data_end, &iph) < 0) {
		metrics_inc(METRICS_PASS, pkt_len);
		return XDP_PASS;
	}

	__u32 saddr = bpf_ntohl(iph->saddr);
	int *blocked = map_lookup(saddr);
	if (blocked && *blocked) {
		metrics_inc(METRICS_DROP, pkt_len);
		return XDP_DROP;
	}

	metrics_inc(METRICS_PASS, pkt_len);
	return XDP_PASS;
}
