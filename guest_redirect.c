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
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsk_map SEC(".maps");

char fmt1[] = "in xdp program\n";
char fmt2[] = "found a hit in the map\n";
char fmt3[] = "redirect returned %d\n";


SEC("xdp")
int xdp_redirect(struct xdp_md *ctx)
{
	int idx = 0;

	bpf_trace_printk(fmt1, sizeof(fmt1));
	int result =  bpf_redirect_map(&xsk_map, idx, XDP_PASS);
	bpf_trace_printk(fmt3, sizeof(fmt3), result);
	/*
	int* rec = bpf_map_lookup_elem(&xsk_map, &idx);
	if(rec)
	{
		bpf_trace_printk(fmt2, sizeof(fmt2));
		int result =  bpf_redirect_map(&xsk_map, idx, 0);
		bpf_trace_printk(fmt3, sizeof(fmt3), result);
		return result;
	}
	*/
	return result;
}

char _license[] SEC("license") = "GPL";

