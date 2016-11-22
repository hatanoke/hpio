/* posix system call packet generator using hpio */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <pthread.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#define pr_info(fmt, ...) fprintf(stdout, "%s: " fmt, __func__, ##__VA_ARGS__)
#define pr_err(fmt, ...) fprintf(stderr, "%s: " fmt, __func__, ##__VA_ARGS__)


#include "../../kmod/hpio.h"	/* struct hpio_hdr */


#define MAX_CPU		64
#define MAX_PKTLEN	HPIO_PACKET_SIZE
#define MAX_BULKNUM	HPIO_SLOT_NUM
#define UDP_DST_PORT	60000
#define UDP_SRC_PORT	60001


/* ppktgen program body structure */
struct ppktgen_body {
	char *devpath;	/* hpio character device path */

	struct in_addr dst_ip;
	struct in_addr src_ip;
	unsigned char dst_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];

	unsigned short	udp_dst;	/* udp dst port */
	unsigned short	udp_src;	/* udp src port */

	int ncpus;	/* number of cpus */
	int nthreads;	/* number of threads */

	struct hpio_slot {
		struct hpio_hdr hdr;
		char pkt[MAX_PKTLEN];
	} __attribute__ ((__packed__)) slot;	/* hpio slot pkt buffer */

	char *pkt;	/* &slot.pkt*/
	int len;	/* length of the packet */
	int bulk;	/* number of bulked packets at one writev() */
	int interval;	/* usec interval */

	unsigned long count;	/* count of excuting writev() */
};


/* ppktgen thread structure */
struct ppktgen_thread {
	pthread_t	tid;
	int fd;		/* write fd for hpio character device */
	int cpu;	/* cpu this thread running on */

	unsigned long count;

	struct ppktgen_body *pbody;
};



/* global variable */
static int caught_signal = 0;



/* ppktgen thread body on a cpu */
void * ppktgen_thread(void *arg)
{
	int n, cnt;
	cpu_set_t target_cpu_set;
	struct ppktgen_thread *pt = (struct ppktgen_thread *)arg;
	struct ppktgen_body *pbody = pt->pbody;
	struct iovec iov[MAX_BULKNUM];

	/* pin this thread to a cpu */
        CPU_ZERO(&target_cpu_set);
	CPU_SET(pt->cpu, &target_cpu_set);
	pthread_setaffinity_np(pt->tid, sizeof(cpu_set_t), &target_cpu_set);

	/* initialize packet iovec buffer */
	for (n = 0; n < pbody->bulk; n++) {
		iov[n].iov_base = &pbody->slot;	/* fill the ptr to the slot */
		iov[n].iov_len = pbody->len + sizeof(struct hpio_hdr);
	}

	pr_info("start to writev() packets on cpu %d\n", pt->cpu);

	/* write packets */
	while (1) {
		if (caught_signal)
			break;

		cnt = writev(pt->fd, iov, pbody->bulk);
		if (cnt < 0) {
			pr_err("writev() failed on cpu %d\n", pt->cpu);
			exit (EXIT_FAILURE);
		}

		if (pt->count) {
			pt->count--;
			if (pt->count < 1)
				break;
		}

		if (pbody->interval)
			usleep(pbody->interval);
	}

	return NULL;
}





void sig_handler(int sig)
{
	if (sig == SIGINT)
		caught_signal = 1;
}

int count_online_cpus(void)
{
	cpu_set_t cpu_set;

	if (sched_getaffinity(0, sizeof(cpu_set_t), &cpu_set) == 0)
		return CPU_COUNT(&cpu_set);

	return -1;
}


/* from netmap pkt-gen.c */
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

void build_tx_packet(struct ppktgen_body *pbody)
{
	struct ethhdr *eth;
	struct ip *ip;
	struct udphdr *udp;

	/* build ether header */
	eth = (struct ethhdr *)pbody->slot.pkt;
	memcpy(eth->h_dest, pbody->dst_mac, ETH_ALEN);
	memcpy(eth->h_source, pbody->src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	/* build ip header */
	ip = (struct ip*)(eth + 1);
	ip->ip_v	= IPVERSION;
	ip->ip_hl	= 5;
	ip->ip_id	= 0;
	ip->ip_tos	= IPTOS_LOWDELAY;
	ip->ip_len	= htons(pbody->len - sizeof(*eth));
	ip->ip_off	= 0;
	ip->ip_ttl	= 16;
	ip->ip_p	= IPPROTO_UDP;
	ip->ip_dst	= pbody->dst_ip;
	ip->ip_src	= pbody->src_ip;
	ip->ip_sum	= 0;
	ip->ip_sum	= wrapsum(checksum(ip, sizeof(*ip), 0));

	/* build udp header */
	udp = (struct udphdr *)(ip + 1);
	udp->uh_dport	= pbody->udp_dst;
	udp->uh_sport	= pbody->udp_src;
	udp->uh_ulen	= htons(pbody->len - sizeof(*eth) - sizeof(*ip));
}



void usage(void)
{
	printf("ppktgen usage:\n"
	       "\t -i: path to hpio device\n"
	       "\t -d: destination IPv4 address\n"
	       "\t -s: source IPv4 address\n"
	       "\t -D: destination MAC address\n"
	       "\t -S: source MAC address\n"
	       "\t -l: length of a packet\n"
	       "\t -n: number of threads\n"
	       "\t -b: number of bulked packets\n"
	       "\t -c: number of executing writev() on each cpu\n"
	       "\t -t: packet transmit interval (usec)\n"
		);
}

int main(int argc, char **argv)
{

	int fd, ch, n, rc;
	int dmacbuf[ETH_ALEN], smacbuf[ETH_ALEN];
	char buf[16];		/* for printing parameters to stdout */
	struct ppktgen_body ppktgen;
	struct ppktgen_thread pt[MAX_CPU];

	memset(dmacbuf, 0, sizeof(dmacbuf));
	memset(smacbuf, 0, sizeof(smacbuf));

	memset(&ppktgen, 0, sizeof(ppktgen));
	ppktgen.ncpus = count_online_cpus();
	ppktgen.nthreads = 1;
	ppktgen.bulk = 1;
	ppktgen.len = 64;
	ppktgen.udp_dst = htons(UDP_DST_PORT);
	ppktgen.udp_src = htons(UDP_SRC_PORT);

	while ((ch = getopt(argc, argv, "i:d:s:D:S:l:n:b:c:t:")) != -1) {
		switch (ch) {
		case 'i' :
			/* hpio device path */
			ppktgen.devpath = optarg;
			break;

		case 'd' :
			/* dst ip addr */
			rc = inet_pton(AF_INET, optarg, &ppktgen.dst_ip);
			if (rc != 1) {
				pr_err("invalid dst ip %s\n", optarg);
				return -1;
			}
			break;

		case 's' :
			/* src ip addr */
			rc = inet_pton(AF_INET, optarg, &ppktgen.src_ip);
			if (rc != 1) {
				pr_err("invalid src ip %s\n", optarg);
				return -1;
			}
			break;

		case 'D' :
			/* dst mac addr */
			rc = sscanf(optarg, "%x:%x:%x:%x:%x:%x",
				    &dmacbuf[0], &dmacbuf[1], &dmacbuf[2],
				    &dmacbuf[3], &dmacbuf[4], &dmacbuf[5]);
			if (rc == EOF) {
				pr_err("invalid dst mac %s\n", optarg);
				return -1;
			}
			for (n = 0; n < ETH_ALEN; n++)
				ppktgen.dst_mac[n] = dmacbuf[n];
			break;

		case 'S' :
			/* src mac addr */
			rc = sscanf(optarg, "%x:%x:%x:%x:%x:%x",
				    &smacbuf[0], &smacbuf[1], &smacbuf[2],
				    &smacbuf[3], &smacbuf[4], &smacbuf[5]);
			if (rc == EOF) {
				pr_err("invalid src mac %s\n", optarg);
				return -1;
			}
			for (n = 0; n < ETH_ALEN; n++)
				ppktgen.src_mac[n] = smacbuf[n];
			break;

		case 'l' :
			/* length of the packet */
			ppktgen.len = atoi(optarg);
			if (ppktgen.len < 64 || ppktgen.len > MAX_PKTLEN) {
				pr_err("pkt len must be >= 64, < %d\n",
				       MAX_PKTLEN);
				return -1;
			}
			break;


		case 'n' :
			/* number of threads */
			ppktgen.nthreads = atoi(optarg);
			if (ppktgen.nthreads < 1 ||
			    ppktgen.nthreads > ppktgen.ncpus) {
				pr_err("num of threads must be > 0, "
				       "< %d\n", ppktgen.ncpus);
				return -1;
			}
			break;

		case 'b' :
			/* number of bulked packets */
			ppktgen.bulk = atoi(optarg);
			if (ppktgen.bulk < 1 || ppktgen.bulk > MAX_BULKNUM) {
				pr_err("num of bulked packets must be > 0, "
				       "< %d\n", MAX_BULKNUM);
				return -1;
			}
			break;

		case 'c' :
			/* writev() count */
			rc = sscanf(optarg, "%lu", &ppktgen.count);
			if (rc == EOF) {
				pr_err("invalid count %s\n", optarg);
				return -1;
			}
			break;

		case 't' :
			/* packet transmit interval */
			ppktgen.interval = atoi(optarg);
			if (ppktgen.interval < -1) {
				pr_err("interval must be > 0\n");
				return -1;
			}
			break;

		default:
			usage();
			return -1;
		}
	}


	/* print parameters */
	pr_info("============ Parameters ============\n");
	pr_info("dev:               %s\n", ppktgen.devpath);

	inet_ntop(AF_INET, &ppktgen.dst_ip, buf, sizeof(buf));
	pr_info("dst IP:            %s\n", buf);

	inet_ntop(AF_INET, &ppktgen.src_ip, buf, sizeof(buf));
	pr_info("src IP:            %s\n", buf);

	pr_info("dst MAC:           %02x:%02x:%02x:%02x:%02x:%02x\n",
		dmacbuf[0], dmacbuf[2], dmacbuf[2],
		dmacbuf[3], dmacbuf[4], dmacbuf[5]);

	pr_info("src MAC:           %02x:%02x:%02x:%02x:%02x:%02x\n",
		smacbuf[0], smacbuf[2], smacbuf[2],
		smacbuf[3], smacbuf[4], smacbuf[5]);

	pr_info("packet size:       %d\n", ppktgen.len);
	pr_info("number of bulk:    %d\n", ppktgen.bulk);
	pr_info("number of threads: %d\n", ppktgen.nthreads);
	pr_info("count of writev(): %lu\n", ppktgen.count);
	pr_info("transmit interval: %d\n", ppktgen.interval);
	pr_info("====================================\n");


	/* initialize slot and build packet */
	ppktgen.slot.hdr.pktlen = ppktgen.len;
	build_tx_packet(&ppktgen);
	
	/* open hpio fd */
	fd = open(ppktgen.devpath, O_RDWR);
	if (fd < 0) {
		pr_err("cannot open device %s\n", ppktgen.devpath);
		perror("open");
		return -1;
	}

	/* create threads */
	for (n = 0; n < ppktgen.nthreads; n++) {
		pt[n].fd = fd;
		pt[n].cpu = n;
		pt[n].pbody = &ppktgen;
		pt[n].count = ppktgen.count;

		rc = pthread_create(&pt[n].tid, NULL, ppktgen_thread, &pt[n]);
		if (rc < 0) {
			perror("pthread_create");
			exit(EXIT_FAILURE);
		}
	}

	/* set signal */
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		perror("cannot set signal\n");
		exit (EXIT_FAILURE);
	}

	/* thread join */
	for (n = 0; n < ppktgen.nthreads; n++)
		pthread_join(pt[n].tid, NULL);


	close (fd);

	return 0;
}
