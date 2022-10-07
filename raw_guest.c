#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <locale.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <time.h>

struct my_socket {
  int fd;
  uint64_t rx_packets;
  uint64_t rx_bytes;
  uint64_t tx_packets;
  uint64_t tx_bytes;
};

#define handle_error(msg) { fprintf(stderr, "%s %s(%d)\n", msg, strerror(errno), errno); exit(1); }

#define DEBUG 0
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
#define RING_SIZE 1
#include "xsk_ops.h"


static uint64_t gettime()
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(1);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static void *stats_poll(void *arg)
{
        unsigned int interval = 2;
        struct my_socket *xsk = arg;
        setlocale(LC_NUMERIC, "en_US");
        uint64_t prev_time = 0, prev_rx_packets = 0, cur_time, cur_rx_packets;
        double period = 0.0, rx_pps = 0.0;
        while (1) {
                sleep(interval);
                if (prev_time == 0) {
                          prev_time = gettime();
                          prev_rx_packets = READ_ONCE(xsk->rx_packets);
                          continue;
                }
                cur_time = gettime();
                period = ((double) (cur_time - prev_time) / NANOSEC_PER_SEC);
		prev_time = cur_time;
                cur_rx_packets = READ_ONCE(xsk->rx_packets);
                rx_pps = (cur_rx_packets - prev_rx_packets) / period;
		prev_rx_packets = cur_rx_packets;
                printf("rx pps: %'10.0f\n", rx_pps);
        }
}

#define MTU_SIZE 2048
#define MAX_MSG 32

void dumb_poll(struct my_socket *sock)
{
	struct mmsghdr messages[MAX_MSG] = {0};
	char buffers[MAX_MSG][MTU_SIZE];
	struct iovec iovecs[MAX_MSG] = {0};

	/* Setup recvmmsg data structures. */
	int i;
	for (i = 0; i < MAX_MSG; i++) {
		char *buf = &buffers[i][0];
		struct iovec *iovec = &iovecs[i];
		struct mmsghdr *msg = &messages[i];
 
		msg->msg_hdr.msg_iov = iovec;
		msg->msg_hdr.msg_iovlen = 1;
 
		iovec->iov_base = &buf[0];
		iovec->iov_len = MTU_SIZE;
	}
	printf("done setting up recvmsg\n");
	while (1) {
		int r = recvmmsg(sock->fd, messages, MAX_MSG, MSG_WAITFORONE, NULL);
		if (r == 0) {
			handle_error("error waiting for packet");
		}
		if (r < 0) {
			if (errno == EINTR)  continue;
			handle_error("error waiting for packet");
		}
		else
		{
			for (i = 0; i < MAX_MSG; i++) {
				struct mmsghdr *msg = &messages[i];
				sock->rx_bytes += msg->msg_len;
				msg->msg_len = 0;
			}
			sock->rx_packets += r;
		}
	}
	
}

int main()
{
	int s = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(s < 0)
		handle_error("error opening raw socket");

        struct my_socket xsk_sock;
        memset(&xsk_sock, 0, sizeof(struct my_socket));
        xsk_sock.fd = s;
        int ret;
        pthread_t stats_poll_thread;
	printf("creating stats thread\n");
        ret = pthread_create(&stats_poll_thread, NULL, stats_poll, &xsk_sock);
        if (ret) {
              handle_error("error creating stats thraed");
        }
	dumb_poll(&xsk_sock);
	printf("UNREACHABLE!");
}
