#include <stdio.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

const char *FILE_NAME = "/tmp/bpf/map1";
#define pin_dir_path "/sys/fs/bpf/xdp/globals/"
const char *pin_path = pin_dir_path "created_map";
const char *map_name = "created_map";
const int key_size = 4;
const int value_size = 4;
const int max_entries = 1;
int main()
{
	int map = bpf_map_create(BPF_MAP_TYPE_ARRAY, map_name, key_size, value_size, max_entries, NULL);
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
