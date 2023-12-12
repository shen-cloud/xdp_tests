/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP stats program\n"
	" - Finding xdp_stats_map via --dev name info\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <errno.h>


#include <bpf/bpf.h>
/* Lesson#1: this prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */
#include <bpf/libbpf.h> /* libbpf_num_possible_cpus */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(-1);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static const char *xdp_action_names[XDP_ACTION_MAX] = {
	[XDP_ABORTED]  = "XDP_ABORTED",
	[XDP_DROP]     = "XDP_DROP",
	[XDP_PASS]     = "XDP_PASS",
	[XDP_TX]       = "XDP_TX",
	[XDP_REDIRECT] = "XDP_REDIRECT",
};

static const char *action2str(int action)
{
	if (action < XDP_ACTION_MAX)
		return xdp_action_names[action];
	return NULL;
}

struct record {
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};

typedef unsigned long     uintptr_t;
static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

struct stats_record {
	struct record stats[XDP_ACTION_MAX];
};

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print_header()
{
	/* Print stats "header" */
	printf("%-12s\n", "XDP-action");
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	__u64 packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */
	int i;

	stats_print_header(); /* Print stats "header" */

	/* Print for each XDP actions stats */
	for (i = 0; i < XDP_ACTION_MAX; i++)
	{
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
			" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";
		const char *action = action2str(i);

		rec  = &stats_rec->stats[i];
		prev = &stats_prev->stats[i];

		period = calc_period(rec, prev);
		if (period == 0)
		       return;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		pps     = packets / period;

		bytes   = rec->total.rx_bytes   - prev->total.rx_bytes;
		bps     = (bytes * 8)/ period / 1000000;

		printf(fmt, action, rec->total.rx_packets, pps,
		       rec->total.rx_bytes / 1000 , bps,
		       period);
	}
	printf("\n");
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(const char *pin_dir, int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = 64;
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;
	union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

	printf("reading for a BPF map at %s with fd %d\n", pin_dir, fd);

	// attr.pathname = pin_dir;
	attr.map_fd = fd;
	attr.key = ptr_to_u64(&key);
	attr.value = ptr_to_u64(values);
	if (syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM,  &attr, sizeof(attr)) != 0) {
		fprintf(stderr, "Failed to read from BPF map: %s\n", strerror(errno));
		return;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
}

static bool map_collect(const char *pin_dir, int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		map_get_value_percpu_array(pin_dir, fd, key, &value);
		break;
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}

	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes   = value.rx_bytes;
	return true;
}

static void stats_collect(const char *pin_dir, int fd, __u32 map_type,
			  struct stats_record *stats_rec)
{
	/* Collect all XDP actions stats  */
	__u32 key;

	for (key = 0; key < XDP_ACTION_MAX; key++) {
		map_collect(pin_dir, fd, map_type, key, &stats_rec->stats[key]);
	}
}

static int stats_poll(const char *pin_dir, int map_fd,
		      __u32 map_type, int interval)
{
	struct bpf_map_info info = {};
	struct stats_record prev, record = { 0 };

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Get initial reading quickly */
	stats_collect(pin_dir, map_fd, map_type, &record);
	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */

		stats_collect(pin_dir, map_fd, map_type, &record);
		stats_print(&record, &prev);
		// close(map_fd);
		sleep(interval);
	}

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	char pin_dir[128];

    sprintf(pin_dir, "/sys/fs/bpf/xdp/globals/%s", "xdp_stats_map");
    printf("Looking for a BPF map at %s\n", pin_dir);

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = ((void *)pin_dir);

	struct bpf_map_info info = { 0 };
	int stats_map_fd;
	int interval = 2;
	int len, err;

	for ( ;; ) {
		int stats_map_fd = syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
		if (stats_map_fd < 0) {
			perror("bpf_obj_get");
			return EXIT_FAILURE;
		}

		err = stats_poll(pin_dir, stats_map_fd, BPF_MAP_TYPE_PERCPU_ARRAY, interval);
		// close(stats_map_fd);
		if (err < 0)
			return err;
	}

	return EXIT_SUCCESS;
}
