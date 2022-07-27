#include <stdio.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define pin_dir_path "/sys/fs/bpf/xdp/globals/"
const char *pin_path = pin_dir_path "xsk_map";
const char *map_name = "xsk_map";
const int key_size = 4;
const int value_size = 4;
const int max_entries = 1;
int main()
{
	printf("making map at %s\n", pin_path);
	int map = bpf_map_create(BPF_MAP_TYPE_XSKMAP, map_name, key_size, value_size, max_entries, NULL);
	if(map < 0)
	{
			printf("failed to get map %s\n", strerror(map));
	}
	int ret = bpf_obj_pin(map, pin_path);
	if(ret < 0)
	{
			printf("failed to pin map %s\n", strerror(map));
	}
}
