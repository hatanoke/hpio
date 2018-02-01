#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <hpio.h>

static uint16_t
checksum (const void * data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = data;
        uint32_t i;

        /* Checksum all the pairs of bytes first... */
        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }
        /*
         * If there's a single byte left over, checksum it, too.
         * Network byte order is big-endian, so the remaining byte is
         * the high byte.
         */

        if (i < len) {
                sum += addr[i] << 8;
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }

        return sum;
}

static u_int16_t
wrapsum (u_int32_t sum)
{
        sum = ~sum & 0xFFFF;
        return (htons(sum));
}


void build_packet(char *buf, int len)
{
	struct hpio_hdr *h;
	struct ethhdr *eth;
	struct ip *ip;
	struct udphdr *udp;

	memset(buf, 0, len + sizeof(*h));

	h = (struct hpio_hdr *)buf;
	h->version = HPIO_HDR_VERSION;
	h->hdrlen = sizeof(*h);
	h->pktlen = len;

	eth = (struct ethhdr *)(h + 1);

	eth->h_dest[0] = 0x52;
	eth->h_dest[1] = 0x54;
	eth->h_dest[2] = 0x00;
	eth->h_dest[3] = 0x12;
	eth->h_dest[4] = 0x35;
	eth->h_dest[5] = 0x02;
	eth->h_source[0] = 0x08;
	eth->h_source[1] = 0x00;
	eth->h_source[2] = 0x27;
	eth->h_source[3] = 0xe7;
	eth->h_source[4] = 0x6c;
	eth->h_source[5] = 0x78;

	eth->h_proto = htons(ETH_P_IP);

	ip = (struct ip*)(eth + 1);
	ip->ip_v	= IPVERSION;
	ip->ip_hl	= 5;
	ip->ip_len	= htons(len - sizeof(*eth));
	ip->ip_ttl	= 16;
	ip->ip_p	= IPPROTO_UDP;
	ip->ip_src.s_addr	= inet_addr("10.0.2.15");
	ip->ip_dst.s_addr	= inet_addr("192.168.0.1");
	ip->ip_sum	= wrapsum(checksum(ip, sizeof(*ip), 0));

	udp = (struct udphdr *)(ip + 1);
	udp->uh_ulen = htons(len - sizeof(*eth) - sizeof(*ip));
	udp->uh_dport = htons(50000);
	udp->uh_sport = htons(50000);

	return;
}


int main(int argc, char **argv)
{
	int fd, n, r;
	char *dev = argv[1], buf[1024];
	struct sockaddr_ll sll;
	struct msghdr m;
	struct iovec iov[8];
	
	fd = socket(AF_HPIO, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0) {
		perror("socket");
		return -1;
	}
	printf("socket %d\n", fd);


	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_HPIO;
	sll.sll_ifindex = if_nametoindex(dev);

	printf("go go bind!\n");
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind");
		return -1;
	}


	/* prepare packet and buffer */
	build_packet(buf, 512);
	memset(&m, 0, sizeof(m));
	m.msg_iov = iov;
	m.msg_iovlen = 8;
	for (n = 0; n < 8; n++) {
		iov[n].iov_base = buf;
		iov[n].iov_len = sizeof(buf);
	}
	

	/* send packet */
	for (n = 0; n < 10; n++) {
		r = sendmsg(fd, &m, 0);
		printf("%d packet xmited\n", r);
		if (r < 0) {
			perror("sendmsg");
			break;
		}			
	}

	close(fd);
}
