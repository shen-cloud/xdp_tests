
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include "config.h"

#define handle_error(msg) { fprintf(stderr, "%s %s(%d)\n", msg, strerror(errno), errno); exit(1); }
// const char* pathname = "/tmp/container1/uds";
// #define QUEUE 0
#define XSK_MAX_ENTRIES 1
#define OLD_KERNEL 1
// #define HOST_MODE
// #define ROCKY
#ifdef ROCKY
static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}
#endif

struct ifpair
{
	int container;
	int host;
};

int make_uds(const char* path)
{
	unlink(path);
	int uds = socket(AF_UNIX, SOCK_STREAM, 0);
	if(uds < 0)
		handle_error("error opening uds\n");
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
	int err = bind(uds, (struct sockaddr*)&addr, sizeof(addr));
	if(err)
		handle_error("error binding socket");
	err = listen(uds, 10);
	if(err)
		handle_error("error listening to socket");
	int fd = accept(uds, NULL, NULL);
	if(fd < 0)
		handle_error("error accepting");

	return fd;

}

void enter_mnt_ns(int pid)
{
	printf("entering mnt_ns\n");
#if OLD_KERNEL
	char buf[1000] = {0};
	sprintf(buf, "/proc/%d/ns/mnt", pid);
	int fd = open(buf, O_RDONLY);
	if(fd < 0)
		handle_error("error opening pidfd");
#else 

	int fd = syscall(SYS_pidfd_open, pid, 0);
	if(fd < 0)
		handle_error("error opening pidfd");
#endif
	
	int err = setns(fd, CLONE_NEWNS);
	if(err)
		handle_error("error entering mount namespace");
}
void enter_ns(int pid)
{
#if OLD_KERNEL
	char buf[1000] = {0};
	sprintf(buf, "/proc/%d/ns/net", pid);
	int fd = open(buf, O_RDONLY);
	if(fd < 0)
		handle_error("error opening pidfd");
#else 

	int fd = syscall(SYS_pidfd_open, pid, 0);
	if(fd < 0)
		handle_error("error opening pidfd");
#endif
	
	int err = setns(fd, CLONE_NEWNET);
	if(err)
		handle_error("error entering namespace");
}

int xdp_socket()
{
	int xsk = socket(AF_XDP, SOCK_RAW, 0);
	if(xsk < 0)
		handle_error("error making xsk");
	return xsk;
}

void send_fd(int uds, int xsk)
{
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct msghdr msg;
	struct iovec iov;
	int value = 0;

	iov.iov_base = &value;
	iov.iov_len = sizeof(int);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = CMSG_LEN(sizeof(int));

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));

	*(int *)CMSG_DATA(cmsg) = xsk;
	int ret = sendmsg(uds, &msg, 0);
	if(ret < 0)
		handle_error("error sending socket");
}

int get_pid(int uds)
{
#ifdef ROCKY
	socklen_t len;
#else
	int len;
#endif
	struct ucred ucred;

	len = sizeof(struct ucred);

	if (getsockopt(uds, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
		handle_error("error getting peer pid");
	}

	printf("got peer pid %d\n", ucred.pid);
	return ucred.pid;

}

// assumes the file just contains an int
int get_filedata(const char* path)
{
	char buf[256];
	int file = open(path, O_RDONLY);
	if (file < 0)
		handle_error("error opening file");
	int err = read(file, buf, sizeof(buf));
	if(err <= 0)
		handle_error("error reading file");
	int ret = atoi(buf);
	if(ret == 0)
		handle_error("error converting to int");
	return ret;
}

// should turn this into threads, turns out namespaces are per-thread
struct ifpair get_ifidxs(int ns_pid)
{
	printf("trying to get ifidx info from nspid %d\n", ns_pid);
	struct ifpair *shared = mmap(NULL, sizeof(struct ifpair),
				     PROT_READ | PROT_WRITE,
				     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED)
		handle_error("error making a shared mapping");
	int pid = fork();
	if (pid < 0)
		handle_error("error forking");
	if (pid == 0)
	{
		printf("in child\n");
		enter_mnt_ns(ns_pid);
		shared->container = get_filedata("/sys/class/net/eth0/ifindex");
		shared->host = get_filedata("/sys/class/net/eth0/iflink");
		exit(0);
		printf("UNREACHABLE");

	}
	else
	{
		printf("in parent\n");
		struct ifpair idxs;
		printf("waiting for child\n");
		int ret = waitpid(pid, NULL, 0);
		printf("child returned\n");
		if(ret <= 0)
			handle_error("error waiting for child");
		memcpy(&idxs, shared, sizeof(struct ifpair));
		printf("got indexes: host: %d, container: %d\n", idxs.host, idxs.container);
		ret = munmap(shared, sizeof(struct ifpair));
		if (ret < 0)
			handle_error("error unmapping a shared mapping");
		return idxs;
	}
}

void set_limit(int pid, long limit)
{
	struct rlimit rlimit = {.rlim_cur=limit, .rlim_max=limit};
	int err = prlimit(pid, RLIMIT_MEMLOCK, &rlimit, NULL);
	if(err)
		handle_error("setting limit failed");
}

void wait_for_msg(int uds)
{
	printf("waiting for container to send a message\n");
	char buf[64];
	int bytes_read = read(uds, buf, sizeof(buf)-1);
	if(bytes_read <= 0)
		handle_error("failed to wait for container");
	printf("got message from container: %s\n", buf);
	/*
	char* ifidx_str = strstr(buf, "ifidx") + strlen("ifidx ");
	if(ifidx_str == NULL)
		handle_error("error getting ifidx from string");
	int ifidx = atoi(ifidx_str);
	printf("ifidx: %s, %d\n", ifidx_str, ifidx);
	if(ifidx ==0)
		handle_error("error making ifidx an int");
	*/
	// return ifidx;

}
// we have already entered the container ns, and therefore bind on /eth0
void bind_xsk(int xsk, int ifidx, int queue)
{

	printf("binding to device %d, queue %d\n", ifidx, queue);
	struct sockaddr_xdp sxdp;
	memset(&sxdp, 0, sizeof(sxdp));
        sxdp.sxdp_family = PF_XDP; 
	sxdp.sxdp_ifindex = ifidx;
	sxdp.sxdp_queue_id = queue;
#if ZERO_COPY
	sxdp.sxdp_flags = XDP_ZEROCOPY;
	printf("enable zero copy\n");
#else
	sxdp.sxdp_flags = XDP_USE_NEED_WAKEUP;
#endif
	if (bind(xsk, (struct sockaddr *)&sxdp, sizeof(struct sockaddr_xdp))) {
		handle_error("bind socket failed");
	}
	printf("bound to socket\n");

}

void add_to_xsk_map(int xsk, const char* xsk_map_name, int container_pid, int queue)
{
	union bpf_attr attr;
	int fd_copy = xsk;
	int map;
	char buf[128];

	sprintf(buf, "/sys/fs/bpf/xdp/globals/%s", xsk_map_name);
	printf("looking for a bpf map at %s\n", buf);
	if(access(buf, F_OK) == 0)
	{
		memset(&attr, 0, sizeof(attr));
#ifdef ROCKY
		attr.pathname = ptr_to_u64(((void *)buf));
#else
		attr.pathname = ((void *)buf);
#endif

		map = syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
		if(map < 0)
			handle_error("error opening xsk map");

		printf("got a fd to the map at %d\n", map);

	}
	else
	{
		printf("DIDNT FIND MAP\n");
		return;

		/*
		ret = mkdir("/sys/fs/bpf/xdp", 0);
		if (ret < 0)
			handle_error("failed to make dir /sys/fs/bpf/xdp");
		ret = mkdir("/sys/fs/bpf/xdp/globals", 0);
		if (ret < 0)
			handle_error("failed to make dir 2");
		*/

		/*
		memset(&attr, 0, sizeof(attr));
		attr.map_type = BPF_MAP_TYPE_XSKMAP;
		attr.key_size = sizeof(int);
		attr.value_size = sizeof(int);
		attr.max_entries = XSK_MAX_ENTRIES;
		map = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
		if (map < 0)
			handle_error("failed to create map in container");
		printf("pinning map in container at path %s\n", XSK_PATH);
		//int ret = bpf_obj_pin(map, XSK_PATH);
		memset(&attr, 0, sizeof(attr));
		attr.pathname = &XSK_PATH[0];
		attr.bpf_fd = map;
		ret = syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
		if (ret < 0)
			handle_error("failed to pin map in container");
		*/
	}
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map;
#ifdef ROCKY
	attr.key = ptr_to_u64(&queue);
	attr.value = ptr_to_u64(&fd_copy);
#else
	attr.key = &queue;
	attr.value = &fd_copy;
#endif
	attr.flags = BPF_ANY;
	int err = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	if(err)
		handle_error("error setting map");
	printf("added xsk to map\n");
	printf("set up xsk map\n");

}

void add_to_dev_map(const char* dev_map_path, int port, int ifidx)
{

	union bpf_attr attr;
	int port_copy = port;
	int idx_copy = ifidx;

	printf("adding key, value %d, %d to map at %s\n", port, ifidx, dev_map_path);

	memset(&attr, 0, sizeof(attr));
#ifdef ROCKY
	attr.pathname = ptr_to_u64(((void *)dev_map_path));
#else
	attr.pathname = ((void *)dev_map_path);
#endif

	int fd = syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if(fd < 0)
		handle_error("error opening dev map");

	printf("got a fd to the map at %d\n", fd);
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
#ifdef ROCKY
	attr.key = ptr_to_u64(&port_copy);
	attr.value = ptr_to_u64(&idx_copy);
#else
	attr.key = &port_copy;
	attr.value = &idx_copy;
#endif
	attr.flags = BPF_ANY;
	int err = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	if(err)
		handle_error("error setting map");
	printf("added to dev map\n");


}

void exec_as_child(const char** args, int num_args)
{
	
	int pid = fork();
	if(pid < 0)
		handle_error("error forking new process");
	if(pid == 0)
	{
		//child
		printf("In child, calling %s\n", args[0]);
		printf("executing command: <");
		for(int i=0; i<num_args; i++)
		{
			printf("%s, ", args[i]);
		}
		printf(">\n");
#ifdef ROCKY
		execvp(args[0], (char *const *)args);
#else
		execvp(args[0], args);
#endif
		printf("UNREACHABLE!!!\n");
	}
	else
	{
		printf("waiting for child to return\n");
		wait(NULL);
		printf("child returned\n");
	}
}

void load_xdp_program(const char* file, const char* section)
{
#ifndef HOST_MODE
	const char *args0[] = {"ip", "link", "set", "dev", "eth0", "xdpgeneric", "none", NULL};
	exec_as_child(args0, sizeof(args0)/sizeof(args0[0]));
	const char *args1[] = {"ip", "link", "set", "dev", "eth0", "xdp", "none", NULL};
	exec_as_child(args1, sizeof(args1)/sizeof(args1[0]));
#endif
	printf("Press Enter to continue...");
    getchar();
	// const char *args2[] = {"ip", "link", "set", "dev", "eth0", "xdp", "obj", file, "sec", section, NULL};
	// exec_as_child(args2, sizeof(args2)/sizeof(args2[0]));
	// xdp-loader load -m skb -s xdp eth0 xdp_tests/guest_prog.o
	// const char *args3[] = {"xdp-loader", "load", "-m", "skb", "-s", "xdp", "eth0", file};
	// exec_as_child(args3, sizeof(args3)/sizeof(args3[0]));
	// // bpftool map pin id 34 /sys/fs/bpf/xdp/globals/xsk_map1
	// const char *args4[] = {"bpftool", "map", "pin", "id", "34", "/sys/fs/bpf/xdp/globals/xsk_map1"};
	// exec_as_child(args4, sizeof(args4)/sizeof(args4[0]));
}

// void pin_map(const char *map_name, const char *pin_path) {
//     int map_fd, err;

//     // Open the map by name
//     map_fd = bpf_obj_get(map_name);
//     if (map_fd < 0) {
//         perror("Error opening map");
//         exit(EXIT_FAILURE);
//     }

//     // Pin the map
//     err = bpf_obj_pin(map_fd, pin_path);
//     if (err) {
//         perror("Error pinning map");
//         close(map_fd);
//         exit(EXIT_FAILURE);
//     }

//     printf("Map '%s' pinned to '%s'\n", map_name, pin_path);
//     close(map_fd);
// }

int get_ifindex()
{
	char buf[16];
#ifdef HOST_MODE
#ifdef ROCKY
	int ifidx_file = open("/sys/class/net/ens1f0/ifindex", O_RDONLY);
#else
	int ifidx_file = open("/sys/class/net/ens1f0np0/ifindex", O_RDONLY);
#endif
#else
	int ifidx_file = open("/sys/class/net/eth0/ifindex", O_RDONLY);
#endif
	if(ifidx_file < 0)
		handle_error("error opening eth0 ifindex file");
	int err = read(ifidx_file, buf, sizeof(buf));
	if(err <= 0)
		handle_error("error reading ifindex file");
	int ifidx = atoi(buf);
	if(ifidx == 0)
		handle_error("error converting ifindex");
	return ifidx;

}

int main(int argc, char** argv)
{

	if (argc != 5)
	{
		printf("usage: socket.o map_path map_key xsk_map_name");
		return -1;
	}
	int map_key = atoi(argv[2]);
	if (map_key == 0)
	{
		printf("usage: socket.o map_path map_key xsk_map_name");
		return -1;
	}

	char* xsk_map_name = argv[3];
	printf("getting uds \n");
	char* pathname = argv[4];
	int uds = make_uds(pathname);
	int queue = QUEUE;

	int pid = get_pid(uds);
#ifdef HOST_MODE
	int ifidx = get_ifindex();
#else
	struct ifpair ifidxs = get_ifidxs(pid);
	add_to_dev_map(argv[1], map_key, ifidxs.host);
	enter_ns(pid);
#endif
	set_limit(pid, 1l<<34); //4G
	printf("got uds %d\n", uds);
	int xsk = xdp_socket();
	printf("got xsk %d\n", xsk);
	send_fd(uds, xsk);
	wait_for_msg(uds);
	// enter_mnt_ns(pid);
#ifdef HOST_MODE
	bind_xsk(xsk, ifidx, queue);
#else
	bind_xsk(xsk, ifidxs.container);
#endif
	load_xdp_program("./guest_prog.o", "xdp");
	// pin_map(xsk_map_name, path_xsk_map1);
	add_to_xsk_map(xsk, xsk_map_name, pid, queue);
	printf("Done\n");

	// char* args[] = {"/bin/bash", NULL};
	// execvp(args[0], args);
	// char* args[] = {"ip", "addr", "show", NULL};
	// execvp(args[0], args);
}
