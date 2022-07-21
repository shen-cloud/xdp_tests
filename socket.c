
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
const char* pathname = "/tmp/container1/uds";


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

int main()
{
	printf("getting uds \n");
	int uds = make_uds(pathname);
	printf("got uds %d\n", uds);
	int xsk = xdp_socket();
	printf("got xsk %d\n", xsk);
	send_fd(uds, xsk);
}
