#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>


/*
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = 4,
	.value_size  = 4,
	.max_entries = 1,
};

*/
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, 32);
    __type(key, int);
    __type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_RDONLY_PROG);
} dev_map SEC(".maps");


static const char fmt1[] = "got udp with src port %d, dest port %d";
static const char fmt2[] = "in host xdp ";
static const char fmt3[] = "got an ip packet";
static const char fmt4[] = "got a udp packet";
static const char fmt5[] = "got %d from redirect";

SEC("xdp")
int xdp_nop(struct xdp_md *ctx)
{
	//int idx = 0;
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	//int size = ctx->data_end - ctx->data;
	struct ethhdr *eth = data;

	bpf_trace_printk(fmt2, sizeof(fmt2));
	if(ctx->data + sizeof(struct ethhdr) > ctx->data_end)
		return XDP_DROP;
	__u16 h_proto = eth->h_proto;
	if (h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	bpf_trace_printk(fmt3, sizeof(fmt3));
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if((void*)iph  + sizeof(struct iphdr) >= data_end)
		return XDP_DROP;

	int header_size = iph->ihl * 4;
	if(header_size < sizeof(struct iphdr))
		return XDP_DROP;
	if((void*)iph + header_size > data_end)
		return XDP_DROP;
	int protocol = iph->protocol;
	if(protocol != IPPROTO_UDP)
		return XDP_PASS;
	bpf_trace_printk(fmt4, sizeof(fmt4));
	struct udphdr *udr = (void*)iph + sizeof(struct iphdr);
	if((void*)udr  + sizeof(struct udphdr) >= data_end)
		return XDP_DROP;
	int port1 = bpf_ntohs(udr->dest);
	int port2 = bpf_ntohs(udr->source);
	bpf_trace_printk(fmt1, sizeof(fmt1), port1, port2);

	int ret = bpf_redirect_map(&dev_map, port1, 0);
	bpf_trace_printk(fmt5, sizeof(fmt5), ret);
	
	return ret;
}

char _license[] SEC("license") = "GPL";

