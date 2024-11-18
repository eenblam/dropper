//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_LPM_TRIE/#example
struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);  //TODO Define a SET_BY_USERSPACE=0 constant; this will fail verification if not updated by userspace
} ipv4_lpm_trie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 255); //TODO make this scalable
} stats_map SEC(".maps");

// drop_packets_by_ip drops packets based on the source IP address.
SEC("xdp")
int drop_packets_by_ip(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check if it's an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .data = ip->saddr,
    };
    __u64 *rule_id = bpf_map_lookup_elem(&ipv4_lpm_trie, &key);
    if (rule_id) {
        // Update stats
        __u64 *stats = bpf_map_lookup_elem(&stats_map, rule_id);
        if (stats) {
            __sync_fetch_and_add(stats, 1);
        }

        return XDP_DROP;
    }


    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
