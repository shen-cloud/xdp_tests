#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

struct key {
	uint32_t prefixlen;
	uint32_t ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 512);
    __uint(key_size, 8); // 4 bytes for prefixlen, 4 for actual data
    __uint(value_size, sizeof(int));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC); //needed for reasons I don't understand, but you get EINVAL otherwise
} lpm_dev SEC(".maps");


/*
static const char fmt1[] = "looking up with key len %u, 'ip' %u\n";
static const char fmt2[] = "in xdp";
*/

SEC("xdp")
int xdp_nop(struct xdp_md *ctx)
{
	// bpf_trace_printk(fmt2, sizeof(fmt2));
	// return XDP_PASS;
	//int idx = 0;
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	//int size = ctx->data_end - ctx->data;
	struct ethhdr *eth = data;

	// bpf_trace_printk(fmt2, sizeof(fmt2));
	if(ctx->data + sizeof(struct ethhdr) > ctx->data_end)
		return XDP_DROP;
	__u16 h_proto = eth->h_proto;
	if (h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	// bpf_trace_printk(fmt3, sizeof(fmt3));
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
	// bpf_trace_printk(fmt4, sizeof(fmt4));
	struct udphdr *udr = (void*)iph + sizeof(struct iphdr);
	if((void*)udr  + sizeof(struct udphdr) >= data_end)
		return XDP_DROP;
	int port1 = bpf_ntohs(udr->dest);
	// int port2 = bpf_ntohs(udr->source);
	struct key k = {.prefixlen=32, .ip=port1};
	// bpf_trace_printk(fmt1, sizeof(fmt1), k.prefixlen, k.ip);
	int *value = bpf_map_lookup_elem(&lpm_dev, &k);
	if(value)
	{
		return bpf_redirect(*value, 0);
	}
	else
		return XDP_PASS;
	// int ret = bpf_redirect_map(&dev_map, port1, 0);
	// bpf_trace_printk(fmt5, sizeof(fmt5), ret);
	
	// return ret;
}

char _license[] SEC("license") = "GPL";

