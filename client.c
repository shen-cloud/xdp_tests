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

#define handle_error(msg) { fprintf(stderr, "%s %s(%d)\n", msg, strerror(errno), errno); exit(1); }
const char* pathname = "/shared/uds";

#define RING_SIZE 1024

struct umem_ring {
	__u32 cached_prod;
	__u32 cached_cons; //actually `size` bigger than consumer
	__u32 size;
	__u32 *producer;
	__u32 *consumer;
	__u64 *ring;
};

struct kernel_ring {
	__u32 cached_prod;
	__u32 cached_cons; //actually `size` bigger than consumer
	__u32 size;
	__u32 *producer;
	__u32 *consumer;
	struct xdp_desc *ring;
};
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
void set_umem(int xsk, long size)
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
	rx->cached_cons = RING_SIZE;
	
}

int main()
{
	int uds = get_uds(pathname);
	printf("got uds %d\n", uds);
	int xsk = get_fd(uds);
	printf("got xsk %d\n", xsk);
	set_umem(xsk, 4096l * 1096l);
	printf("umem set\n");
	struct umem_ring fill, com;
	struct kernel_ring rx;
	setup_rings(xsk, &fill, &com, &rx);
	printf("set up rings\n");

}
