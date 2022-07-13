#include <stdio.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

const char *FILE_NAME = "/tmp/bpf/map1";
#define pin_dir_path "/sys/fs/bpf/"
const char *pin_path = pin_dir_path "map1";
const char *map_name = "xdp_stats_map";
const int key_size = 4;
const int value_size = 4;
const int max_entries = 64;
int main()
{
	int map = bpf_map_create(BPF_MAP_TYPE_HASH, map_name, key_size, value_size, max_entries, NULL);
	if(map < 0)
	{
			printf("failed to get map");
	}
	int ret = bpf_obj_pin(map, pin_path);
	if(ret < 0)
	{
			printf("failed to get map");
	}
}
