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
#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>

#define handle_error(msg) { fprintf(stderr, "%s %s(%d)\n", msg, strerror(errno), errno); exit(1); }
const char* pathname = "/shared/uds";

#define RING_SIZE 2048
#include "xsk_ops.h" //needs RING_SIZE

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
void* set_umem(int xsk, long size)
{
	// should be page-aligned
	void* umem = mmap(NULL,
			  size,
			  PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS,
			  -1, 0);
	if(umem == (void *) -1)
		handle_error("mapping umem failed");

	struct xdp_umem_reg umem_reg = {.addr = umem, 
		                        .len = size, 
					.chunk_size=4096, 
					.headroom=0};
	if(setsockopt(xsk, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg))){
		handle_error("setting umem failed");
	}
	return umem;
}

void setup_rings(int xsk, struct umem_ring *fill, struct umem_ring *com, struct kernel_ring *rx)
{
	int fill_ring_size = RING_SIZE;
	if(setsockopt(xsk, SOL_XDP, XDP_UMEM_FILL_RING, &fill_ring_size, sizeof(int)) < 0){
		handle_error("setting fill ring failed");
	}
	int com_ring_size = RING_SIZE;
	if(setsockopt(xsk, SOL_XDP, XDP_UMEM_COMPLETION_RING, &com_ring_size, sizeof(int)) < 0){
		handle_error("setting completion ring failed");
	}
	/*
	int tx_ring_size = RING_SIZE;
	if(setsockopt(xsk, SOL_XDP, XDP_TX_RING, &tx_ring_size, sizeof(int)) < 0){
		handle_error("setting tx ring failed");
	}
	*/
	int rx_ring_size = RING_SIZE;
	if(setsockopt(xsk, SOL_XDP, XDP_RX_RING, &rx_ring_size, sizeof(int)) < 0){
		handle_error("setting rx ring failed");
	}


	struct xdp_mmap_offsets offs;
	socklen_t optlen = sizeof(offs);
	int err = getsockopt(xsk, SOL_XDP, XDP_MMAP_OFFSETS, &offs, &optlen);
	if(err)
		handle_error("error getting offsets");
	
	void* fill_map = mmap(NULL,
			offs.fr.desc + RING_SIZE * sizeof(__u64),
		   	PROT_READ | PROT_WRITE, 
			MAP_SHARED | MAP_POPULATE,
			xsk,
		  	XDP_UMEM_PGOFF_FILL_RING);
	if(fill_map == MAP_FAILED)
		handle_error("error mapping fill ring");
	fill->size = RING_SIZE;
	fill->producer = fill_map + offs.fr.producer;
	fill->consumer = fill_map + offs.fr.consumer;
	fill->ring = fill_map + offs.fr.desc;
	fill->cached_prod = 0;
	fill->cached_cons = RING_SIZE;

	void* com_map = mmap(NULL,
			offs.cr.desc + RING_SIZE * sizeof(__u64),
		   	PROT_READ | PROT_WRITE, 
			MAP_SHARED | MAP_POPULATE,
			xsk,
		  	XDP_UMEM_PGOFF_COMPLETION_RING);
	if(com_map == MAP_FAILED)
		handle_error("error mapping completion ring");
	com->size = RING_SIZE;
	com->producer = com_map + offs.cr.producer;
	com->consumer = com_map + offs.cr.consumer;
	com->ring = com_map + offs.cr.desc;
	com->cached_prod = 0;
	com->cached_cons = RING_SIZE;

	void* rx_map = mmap(NULL, 
		      offs.rx.desc + RING_SIZE * sizeof(struct xdp_desc),
		      PROT_READ | PROT_WRITE, 
		      MAP_SHARED | MAP_POPULATE,
		      xsk, 
		      XDP_PGOFF_RX_RING);
	if(rx_map == MAP_FAILED)
		handle_error("error mapping completion ring");
	rx->size = RING_SIZE;
	rx->producer = rx_map + offs.rx.producer;
	rx->consumer = rx_map + offs.rx.consumer;
	rx->ring = rx_map + offs.rx.desc;
	rx->cached_prod = 0;
	rx->cached_cons = 0;

	printf("debugging producer for fill: %d\n", debug_umem_prod(fill));
	int num_reserved = xsk_umem_prod_reserve(fill, RING_SIZE/2);
	printf("Reserved %d slots in the umem\n", num_reserved);
	for (int i=0; i<num_reserved; i++)
	{
		xsk_umem_prod_write(fill, i * 4096);
	}
	xsk_umem_prod_submit(fill, num_reserved);
	printf("debugging producer for fill: %d\n", debug_umem_prod(fill));
	printf("debugging consumer for fill: %d\n", debug_umem_cons(fill));
	
}

int get_ifindex()
{
	char buf[16];
	int ifidx_file = open("/sys/class/net/eth0/ifindex", O_RDONLY);
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

void send_msg(int uds, int ifindex)
{
	const char* raw_msg = "bind ifidx %d pls :)";
	char buf[64] = {0};
	int ssize = sprintf(buf, raw_msg, ifindex);
	int bytes_written = write(uds, buf, ssize);
	if(bytes_written <= 0)
		handle_error("error asking for bind");
}

void dumb_poll(int xsk, void* umem, struct umem_ring *fill, struct kernel_ring *rx)
{
	while(1)
	{
		sleep(1);
		//printf("debugging consumer for fill: %d\n", debug_umem_cons(fill));
		int recv_packets = xsk_kr_cons_peek(rx, 1024);
		//printf("recieved %d packets\n", recv_packets);
		if(recv_packets)
		{
			struct xdp_desc* desc = xsk_umem_cons_read(rx);
			printf("got packet with addr %p, len %d\n",(void*) desc->addr, desc->len);
		}
		xsk_kr_cons_release(rx, recv_packets);

		struct xdp_statistics stats;
		socklen_t optlen = sizeof(stats);
		int err = getsockopt(xsk, SOL_XDP, XDP_STATISTICS, &stats, &optlen);
		if (err)
			handle_error("error getting socket stats");

		if (optlen == sizeof(struct xdp_statistics)) {
			printf("xsk stats: rx dropped %ld, rx invalid %ld, rx invalid %ld, rx ring full %ld, rx fill ring empty %ld, tx ring empty %ld\n",
				stats.rx_dropped,
				stats.rx_invalid_descs,
				stats.tx_invalid_descs,
				stats.rx_ring_full,
				stats.rx_fill_ring_empty_descs,
				stats.tx_ring_empty_descs
			);
		}


	}
}

int main()
{
	int uds = get_uds(pathname);
	printf("got uds %d\n", uds);
	int xsk = get_fd(uds);
	printf("got xsk %d\n", xsk);
	void* umem = set_umem(xsk, 4096l * (long)RING_SIZE);
	printf("umem set\n");
	struct umem_ring fill, com;
	struct kernel_ring rx;
	setup_rings(xsk, &fill, &com, &rx);
	printf("set up rings\n");
	int ifidx = get_ifindex();
	send_msg(uds, ifidx);

	dumb_poll(xsk, umem, &fill, &rx);
	sleep(500);

}
