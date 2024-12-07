//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
// Protocol numbers
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

// ethhdr + ip_hdr + max(ip_options) + max(udp_size, tcp_hdr + max(tcp_options))
//=    14 +     20 +              40 + max(8, 20 + 40) = 134
// (Can ignore 802.1q since VLAN filtering happens before it hits the iface)
// ...then, add 1 for initial size field (135)...
// ...and finally round up to a multiple of 8 for alignment (136)
//TODO for some reason, I can't set this lower than 256
const int MAX_BUF_LEN = 256;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1); // Holds only get_stats; drop_ called by entry
} jmp_table SEC(".maps");

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
} drop_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096); //TODO make this scalable; must be multiple of page size!
} sample_map SEC(".maps");


// drop_packets_by_ip drops packets based on the source IP address.
SEC("xdp")
int drop_packets_by_ip(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto pass;

    // Check if it's an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        goto pass;

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        goto pass;

    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .data = ip->saddr,
    };
    __u64 *rule_id = bpf_map_lookup_elem(&ipv4_lpm_trie, &key);
    if (rule_id) {
        // Update stats
        __u64 *stats = bpf_map_lookup_elem(&drop_stats_map, rule_id);
        if (stats) {
            __sync_fetch_and_add(stats, 1);
        } else {
            bpf_printk("no stats for %d", rule_id);
        }

        return XDP_DROP;
    }

pass:
    bpf_tail_call(ctx, &jmp_table, 0);
    // Tail calls only return on failure.
    bpf_printk("tail call to sample_packets failed!\n");
    return XDP_PASS;
}

// sample_packets forwards a sample of packets that haven't been dropped to userspace
SEC("xdp")
int sample_packets(struct xdp_md *ctx) {
    //bpf_printk("stats stats stats!");

    //TODO not sure of ideal tail call order here
    // current: drop -> XDP_DROP -or-> get_stats -> XDP_PASS?
    // alternate: get_stats -> drop -> XDP_[PASS|DROP]?
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


    __u8 length;
    __u8 *src, *dst;
    void *buf;
    struct tcphdr *tcp;
    struct udphdr *udp;
    switch (ip->protocol) {
    case IPPROTO_TCP:
        // Parse TCP header
        // ihl is 4 bits, counting the length of the header in 32-bit words
        struct tcphdr *tcp = (void *)((unsigned char *)ip + (ip->ihl*4));
        if ((void *)(tcp + 1) > data_end) {
            bpf_printk("proto=tcp but header is truncated");
            break;
        }
        // We also want options; doff also counts 32-bit words
        void *hdr_end = (void *)((unsigned char *)tcp + (tcp->doff*4));
        if (hdr_end > data_end) {
            bpf_printk("proto=tcp but header options are truncated");
            break;
        }
        bpf_printk("received TCP");

        length = hdr_end - (void *)data;
        // (ringbuf, size, flags). flags must always be 0.
        buf = bpf_ringbuf_reserve(&sample_map, MAX_BUF_LEN, 0);
        if (!buf) { // NULL if memory unavailable.
            bpf_printk("bpf_ringbuf_reserve failed to allocate");
            return XDP_PASS;
        }

        // No memcpy :(
        src = (unsigned char *)data;
        dst = (unsigned char *)buf;
        dst[0] = length;
        for (int i = 0; i < length; i++) {
            if (src + i >= data_end) {
                bpf_ringbuf_discard(buf, 0);
                bpf_printk("TCP: invalid access at offset %d", i);
                return XDP_PASS;
            }
            if (i+1 > MAX_BUF_LEN) {
                bpf_ringbuf_discard(buf, 0);
                bpf_printk("TCP: invalid access at offset %d", i);
                return XDP_PASS;
            }
            dst[i+1] = src[i];
        }

        // flags=0 for adaptive notification. May want BPF_RB_FORCE_WAKEUP.
        bpf_ringbuf_submit(buf, 0);

        break;
    case IPPROTO_UDP:
        // Parse UDP header
        udp = (void *)((unsigned char *)ip + (ip->ihl*4));
        if ((void *)(udp + 1) > data_end) {
            bpf_printk("UDP: proto=udp but header is incomplete");
            break;
        }
        bpf_printk("UDP: received");

        // Distance from data to end of UDP header
        length = (unsigned char *)(udp) + sizeof(struct udphdr) - (unsigned char*)data;

        if (length > MAX_BUF_LEN - 1) { // -1 to account for size byte
            bpf_printk("UDP: length exceeds MAX_BUF_LEN");
            return XDP_PASS;
        }
        if (data + length > data_end) {
            bpf_printk("UDP: length exceeds data_end");
            return XDP_PASS;
        }

        // (ringbuf, size, flags). flags must always be 0.
        buf = bpf_ringbuf_reserve(&sample_map, MAX_BUF_LEN, 0);
        if (!buf) { // NULL if memory unavailable.
            bpf_printk("UDP: bpf_ringbuf_reserve failed to allocate");
            return XDP_PASS;
        }

        src = (unsigned char *)data;
        dst = (unsigned char *)buf;
        dst[0] = length;
        for (int i = 0; i < length; i++) {
            if (src + i >= data_end) {
                bpf_ringbuf_discard(buf, 0);
                bpf_printk("UDP: invalid access at offset %d", i);
                return XDP_PASS;
            }
            if (i+1 > MAX_BUF_LEN) {
                bpf_ringbuf_discard(buf, 0);
                bpf_printk("UDP: invalid access at offset %d", i);
                return XDP_PASS;
            }
            dst[i+1] = src[i];
        }

        // flags=0 for adaptive notification. May want BPF_RB_FORCE_WAKEUP.
        bpf_ringbuf_submit(buf, 0);
        break;
    default:
        break;
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
