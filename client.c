#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define handle_error(msg) { fprintf(stderr, "%s %s(%d)\n", msg, strerror(errno), errno); exit(1); }
const char* pathname = "/shared/uds";

int get_uds(const char* path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(fd < 0)
		handle_error("error making socket");

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);


	int err = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	if(err < 0)
		handle_error("error connecting to socket");
	return fd;

}

int get_fd(int uds)
{
	int fd;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	int value = 0;
	int len = 0;

	iov.iov_base = &value;
	iov.iov_len = sizeof(int);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = CMSG_LEN(sizeof(int));

	len = recvmsg(uds, &msg, 0);
	if (len < 0) {
		fprintf(stderr, "Recvmsg failed length incorrect.\n");
		return -EINVAL;
	}

	if (len == 0) {
		fprintf(stderr, "Recvmsg failed no data\n");
		return -EINVAL;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	fd = *(int *)CMSG_DATA(cmsg);
	return fd;
}
void *get_umem(long size)
{
	void* umem = mmap(NULL,
			  size,
			  PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS,
			  -1, 0);
	if(umem == (void *) -1)
		handle_error("mapping umem failed");
}

int main()
{
	int uds = get_uds(pathname);
	printf("got uds %d\n", uds);
	int xsk = get_fd(uds);
	printf("got xsk %d\n", xsk);
	void* umem = get_umem(4096l * 4096l);

}
