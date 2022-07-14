#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>


/*
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = 4,
	.value_size  = 4,
	.max_entries = 1,
};

*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} created_map SEC(".maps");



SEC("xdp")
int xdp_nop(struct xdp_md *ctx)
{
	int idx = 0;
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	int size = ctx->data_end - ctx->data;
	struct ethhdr *eth = data;

	if(ctx->data + sizeof(struct ethhdr) > ctx->data_end)
		return XDP_DROP;
	__u16 h_proto = eth->h_proto;
	if (h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = data + sizeof(struct ethhdr);
	if(iph  + sizeof(struct iphdr) >= data_end)
		return XDP_DROP;

	int* rec = bpf_map_lookup_elem(&created_map, &idx);
	if(rec)
		*rec = iph->saddr;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

