
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/un.h>
#include <linux/bpf.h>

#define handle_error(msg) { fprintf(stderr, "%s %s(%d)\n", msg, strerror(errno), errno); exit(1); }
const char* pathname = "/tmp/container1/uds";
#define QUEUE 0
#define XSK_PATH "/sys/fs/bpf/xdp/globals/xsk_map"


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

void enter_ns(int pid)
{
	// could open /sys/<pid>/ns instead
	int fd = syscall(SYS_pidfd_open, pid, 0);
	if(fd < 0)
		handle_error("error opening pidfd");
	
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
	int len;
	struct ucred ucred;

	len = sizeof(struct ucred);

	if (getsockopt(uds, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
		handle_error("error getting peer pid");
	}

	printf("got peer pid %d\n", ucred.pid);
	return ucred.pid;

}

void set_limit(int pid, long limit)
{
	struct rlimit rlimit = {.rlim_cur=limit, .rlim_max=limit};
	int err = prlimit(pid, RLIMIT_MEMLOCK, &rlimit, NULL);
	if(err)
		handle_error("setting limit failed");
}

int wait_for_msg(int uds)
{
	printf("waiting for container to send a message\n");
	char buf[64];
	int bytes_read = read(uds, buf, sizeof(buf)-1);
	if(bytes_read <= 0)
		handle_error("failed to wait for container");
	printf("got message from container: %s\n", buf);
	char* ifidx_str = strstr(buf, "ifidx") + strlen("ifidx ");
	if(ifidx_str == NULL)
		handle_error("error getting ifidx from string");
	int ifidx = atoi(ifidx_str);
	printf("ifidx: %s, %d\n", ifidx_str, ifidx);
	if(ifidx ==0)
		handle_error("error making ifidx an int");
	return ifidx;

}
// we have already entered the container ns, and therefore bind on /eth0
void bind_xsk(int xsk, int ifidx)
{

	printf("binding to device %d, queue %d\n", ifidx, QUEUE);
	struct sockaddr_xdp sxdp;
	memset(&sxdp, 0, sizeof(sxdp));
        sxdp.sxdp_family = PF_XDP; 
	sxdp.sxdp_ifindex = ifidx;
	sxdp.sxdp_queue_id = QUEUE;
	sxdp.sxdp_flags = XDP_USE_NEED_WAKEUP;
	if (bind(xsk, (struct sockaddr *)&sxdp, sizeof(struct sockaddr_xdp))) {
		handle_error("bind socket failed");
	}
	printf("bound to socket\n");

}

void add_to_xsk_map(int xsk, const char* xsk_map_path)
{

	union bpf_attr attr;
	int queue = 0;
	int fd_copy = xsk;

	memset(&attr, 0, sizeof(attr));
	attr.pathname = ((void *)xsk_map_path);

	int fd = syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if(fd < 0)
		handle_error("error opening xsk map");

	printf("got a fd to the map at %d\n", fd);
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = &queue;
	attr.value = &fd_copy;
	attr.flags = BPF_ANY;
	int err = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	if(err)
		handle_error("error setting map");
	printf("set up xsk map\n");


}

void add_to_dev_map(const char* dev_map_path, int port, int ifidx)
{

	union bpf_attr attr;
	int queue = 0;
	int port_copy = port;

	memset(&attr, 0, sizeof(attr));
	attr.pathname = ((void *)dev_map_path);

	int fd = syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
	if(fd < 0)
		handle_error("error opening dev map");

	printf("got a fd to the map at %d\n", fd);
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = &port_copy;
	attr.value = port_copy;
	attr.flags = BPF_ANY;
	int err = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	if(err)
		handle_error("error setting map");
	printf("set up xsk map\n");


}

int main(int argc, char** argv)
{
	printf("getting uds \n");
	int uds = make_uds(pathname);
	int pid = get_pid(uds);
	enter_ns(pid);
	set_limit(pid, 1l<<34); //4G
	printf("got uds %d\n", uds);
	int xsk = xdp_socket();
	printf("got xsk %d\n", xsk);
	send_fd(uds, xsk);
	int ifidx = wait_for_msg(uds);
	add_to_xsk_map(xsk, XSK_PATH);
	bind_xsk(xsk, ifidx);

	// char* args[] = {"/bin/bash", NULL};
	// execvp(args[0], args);
	char* args[] = {"/bin/bash", NULL};
	execvp(args[0], args);
}
