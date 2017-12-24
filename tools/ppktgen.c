/* posix system call packet generator using hpio */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <pthread.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#define pr_info(fmt, ...) fprintf(stdout, "%s: " fmt, \
				  __func__, ##__VA_ARGS__)

#define pr_warn(fmt, ...) fprintf(stdout, "\x1b[1m\x1b[31m"	\
				  "%s:WARN: " fmt "\x1b[0m",	\
				  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "%s:ERR: " fmt,	\
				 __func__, ##__VA_ARGS__)


#include <hpio.h>


#define MAX_CPU		64
#define MAX_PKTLEN	HPIO_PACKET_SIZE
#define MAX_BULKNUM	HPIO_SLOT_NUM
#define UDP_DST_PORT	60000
#define UDP_SRC_PORT	60001

/* TX/RX mode */
#define PP_MODE_TX	1
#define PP_MODE_RX	2

/* ppktgen i/o mode */
#define IO_MODE_HPIO	1
#define IO_MODE_RAW	2
#define IO_MODE_UDP	3

/* timestamp mode */
#define TS_MODE_NONE	0
#define TS_MODE_HW	1
#define TS_MODE_SW	2


/* ppktgen thread structure */
struct ppktgen_thread {
	pthread_t	tid;
	int fd;		/* write fd for hpio character device */
	int cpu;	/* cpu this thread running on */
	int thn;        /* thread number */

	struct hpio_slot {
		struct hpio_hdr hdr;
		char pkt[MAX_PKTLEN];
	} __attribute__ ((__packed__)) slot;	/* hpio slot pkt buffer */

	unsigned long count;

	unsigned long pkt_count;	/* recevied packet count on
					 * this thread for rx mode */

	struct ppktgen_body *pbody;
};


/* ppktgen program body structure */
struct ppktgen_body {
	char *devpath;	/* hpio character device path */

	struct in_addr dst_ip;
	struct in_addr src_ip;
	unsigned char dst_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];

	unsigned short	udp_dst;	/* udp dst port */
	unsigned short	udp_src;	/* udp src port */

	int pp_mode;	/* ppktgen mode, tx or rx */
	int io_mode;	/* packet i/o mode */
	int ts_mode;	/* output timestamp */

	bool per_cpu_rx;	/* per CPU mode for Raw and UDP RX */

	int ncpus;	/* number of cpus */
	int nthreads;	/* number of threads */

	int len;	/* length of the packet */
	int bulk;	/* number of bulked packets at one writev() */
	int interval;	/* usec interval */
	int timeout;	/* timeout (sec) */

	unsigned long count;	/* count of excuting writev() */

	int print_all_cpu_pps;

	struct ppktgen_thread pt[MAX_CPU];

	/* pkt count thread */
	pthread_t pkt_count_tid;
};



/* global variable */
static int caught_signal = 0;
static int hpio_fd = 0;


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

void build_tx_packet(struct ppktgen_body *pbody, struct ppktgen_thread *pt)
{
	struct ethhdr *eth;
	struct ip *ip;
	struct udphdr *udp;

	/* build ether header */
	eth = (struct ethhdr *)pt->slot.pkt;
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
	udp->uh_ulen	= htons(pbody->len -
				sizeof(*eth) - sizeof(*ip));
	udp->uh_dport	= pbody->udp_dst;
	udp->uh_sport	= ((pbody->udp_src + pt->cpu) *
			   0x61C88647) & 0xffff;
	/* XXX: magical value from include/linux/hash.h for RSS */
	
}



/* socket retrieve */

int get_hpio_socket(char *hpio_devpath)
{
	if (hpio_fd == 0)  {
		/* open hpio device first. */
		hpio_fd = open(hpio_devpath, O_RDWR);
		if (hpio_fd < 0) {
			pr_err("cannot open device %s\n", hpio_devpath);
			perror("open");
			return -1;
		}
	}
	return hpio_fd;
}

int get_raw_socket(int cpu, char *dev)
{
	int fd, ret;
	struct sockaddr_ll sll;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		pr_err("cannot create raw socket\n");
		perror("socket");
		return -1;
	}
	
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = if_nametoindex(dev);
	
	ret = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
	if (ret < 0) {
		pr_err("failed to bind raw socket to %s\n", dev);
		perror("bind");
		return -1;
	}

	return fd;
}

int get_udp_socket(int cpu, bool per_cpu_rx, bool rx_mode,
		   struct in_addr dst, int port)
{
	int fd, ret, val = 1;
	socklen_t len;
	struct sockaddr_in saddr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		pr_err("cannot create udp socket\n");
		perror("socket");
		return -1;
	}

	if (rx_mode) {
		/* bind for RX and set SO_REUSEADDR for per_cpu_rx */

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			       &val, sizeof(val)) < 0) {
			pr_err("setsockopt SO_REUSEADDR failed\n");
			perror("setsockopt");
			return -1;
		}

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(port);
		saddr.sin_addr.s_addr = INADDR_ANY;

		ret = bind(fd, (struct sockaddr *)&saddr, sizeof(saddr));
		if (ret < 0) {
			pr_err("failed to bind udp socket\n");
			perror("bind");
			return -1;
		}
	} else {
		/* connect for TX. */
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(port);
		saddr.sin_addr = dst;
		ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
		if (ret < 0) {
			pr_err("failed to connect\n");
			perror("connect");
			return -1;
		}
	}


	if (per_cpu_rx) {
		len = sizeof(cpu);
		ret = setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, len);
		if (ret < 0) {
			pr_err("failed to setsockopt SO_INCOMING_CPU\n");
			perror("setsockopt");
			return -1;
		}
	}

	return fd;
}
	
int get_socket_fd(struct ppktgen_body *pb, struct ppktgen_thread *pt)
{
	int fd = -1, n;
	char *dev = NULL;

	switch(pb->io_mode) {
	case IO_MODE_HPIO :
		fd = get_hpio_socket(pb->devpath);
		break;

	case IO_MODE_RAW :

		/* find device name from hpio device path */
		for (n = strlen(pb->devpath); n > 0; n--) {
			if (pb->devpath[n] == '/') {
				dev = &(pb->devpath[n + 1]);
				break;
			}
		}
		fd = get_raw_socket(pt->cpu, dev);
		break;

	case IO_MODE_UDP :
		fd = get_udp_socket(pt->cpu, pb->per_cpu_rx,
				    (pt->pbody->pp_mode == PP_MODE_RX),
				    pb->dst_ip, UDP_DST_PORT);
		break;
	default :
		pr_err("invalid i/o mode %d\n", pb->io_mode);
		return -1;
	}
	
	return fd;
}


/* ppktgen tx thread body on a cpu */
void * ppktgen_tx_thread(void *arg)
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

	/* initialize slot and build packet */
	pt->slot.hdr.version = HPIO_HDR_VERSION;
	pt->slot.hdr.hdrlen = sizeof(struct hpio_hdr);
	pt->slot.hdr.pktlen = pbody->len;

	if (pbody->io_mode != IO_MODE_UDP) {
		build_tx_packet(pbody, pt);
	}		

	/* initialize packet iovec buffer */
	switch (pbody->io_mode) {
	case IO_MODE_HPIO :
		for (n = 0; n < pbody->bulk; n++) {
			/* fill the ptr to the slot */
			iov[n].iov_base = &pt->slot;
			iov[n].iov_len = pbody->len + sizeof(struct hpio_hdr);
		}
		break;

	case IO_MODE_RAW :
		iov[0].iov_base = &pt->slot.pkt;
		iov[0].iov_len = pbody->len;
		break;

	case IO_MODE_UDP :
		iov[0].iov_base = &pt->slot.pkt;
		iov[0].iov_len = pbody->len - (sizeof(struct ethhdr) +
					       sizeof(struct ip) +
					       sizeof(struct udphdr));
		break;
	}


	/* write packets */
	while (1) {
		if (caught_signal)
			break;

		cnt = writev(pt->fd, iov, pbody->bulk);

		if (cnt < 0) {
			pr_err("writev() failed on cpu %d\n", pt->cpu);
			perror("writev");
			exit (EXIT_FAILURE);
		}

		if (pbody->io_mode == IO_MODE_HPIO)
			pt->pkt_count += cnt;
		else
			pt->pkt_count += 1;

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

/* ppktgen rx thread body on a cpu */
void * ppktgen_rx_thread(void *arg)
{
	int n, cnt;
	char buf[MAX_BULKNUM][MAX_PKTLEN];
	cpu_set_t target_cpu_set;
	struct timeval tv;
	struct hpio_hdr *hdr;
	struct ppktgen_thread *pt = (struct ppktgen_thread *)arg;
	struct ppktgen_body *pbody = pt->pbody;
	struct iovec iov[MAX_BULKNUM];
	struct pollfd x = { .fd = pt->fd, .events = POLLIN };


	/* pin this thread to a cpu */
        CPU_ZERO(&target_cpu_set);
	CPU_SET(pt->cpu, &target_cpu_set);
	pthread_setaffinity_np(pt->tid, sizeof(cpu_set_t), &target_cpu_set);

	/* initialize packet iovec buffer */
	for (n = 0; n < pbody->bulk; n++) {
		iov[n].iov_base = buf[n];	/* fill the ptr to the buf */
		iov[n].iov_len = MAX_PKTLEN;
	}

	/* write packets */
	while (1) {
		if (caught_signal)
			break;

		if (poll(&x, 1, 1000) < 0) {
			pr_err("poll failed on cpu %d\n", pt->cpu);
			perror("poll");
			return NULL;
		}
		if (!x.revents & POLLIN)
			continue;

		cnt = readv(pt->fd, iov, pbody->bulk);
		if (cnt == 0) {
			usleep(100);
			continue;
		}

		if (cnt < 0) {
			pr_err("readv() failed on cpu %d\n", pt->cpu);
			exit (EXIT_FAILURE);
		}

		if (pbody->io_mode == IO_MODE_HPIO)
			pt->pkt_count += cnt;
		else
			pt->pkt_count += 1;

		switch (pbody->ts_mode) {
		case TS_MODE_NONE:
			break;
		case TS_MODE_SW :
			if (gettimeofday(&tv, NULL) < 0) {
				pr_err("gettimeofday failed on cpu %d\n",
					pt->cpu);
				perror("gettimeofday");
				return NULL;
			}
			printf("SW_TIMESTAMP:%ld\n",
			       tv.tv_sec * 1000000+ tv.tv_usec);
			break;
		case TS_MODE_HW :
			for (n = 0; n < cnt; n++) {
				hdr = iov[n].iov_base;
				printf("HW_TIMESTAMP:%ld\n",
				       hdr->tstamp);
			}
			break;
		}
	}

	return NULL;
}

int count_online_cpus(void)
{
	cpu_set_t cpu_set;

	if (sched_getaffinity(0, sizeof(cpu_set_t), &cpu_set) == 0)
		return CPU_COUNT(&cpu_set);

	return -1;
}

/* thread counting packets */
void * ppktgen_count_thread(void *arg)
{
	int n, cpu = count_online_cpus() - 1;
	cpu_set_t target_cpu_set;
	unsigned long pps, before[MAX_CPU], after[MAX_CPU];
	struct ppktgen_body *pbody = arg;

	memset(before, 0, sizeof(unsigned long) + MAX_CPU);
	memset(after, 0, sizeof(unsigned long) + MAX_CPU);

	/* pin this count thread to last CPU core to prevent this thread
	 * from blocked by other tx/rx threads */
	CPU_ZERO(&target_cpu_set);
	CPU_SET(cpu, &target_cpu_set);
	pthread_setaffinity_np(pbody->pkt_count_tid,
			       sizeof(cpu_set_t), &target_cpu_set);
	pr_info("ppktgen_count_thread on CPU %d\n", cpu);

	while (1) {
		if (caught_signal)
			break;

		for (n = 0; n < pbody->nthreads; n++)
			before[n] = pbody->pt[n].pkt_count;

		sleep (1);

		for (n = 0; n < pbody->nthreads; n++)
			after[n] = pbody->pt[n].pkt_count;

		pps = 0;
		for (n = 0; n < pbody->nthreads; n++)
			pps += after[n] - before[n];

		printf("SUM: %lu pps", pps);
		if (pbody->print_all_cpu_pps) {
			for (n = 0; n < pbody->nthreads; n++)
				printf(" CPU%d: %lu pps", n,
				       after[n] - before[n]);
		}
		printf("\n");

		if (pbody->timeout >= 1) {
			pbody->timeout--;
			if (pbody->timeout == 0)
				caught_signal = 1;
		}
	}

	return NULL;
}

void sig_handler(int sig)
{
	if (sig == SIGINT)
		caught_signal = 1;
}




void usage(void)
{
	printf("ppktgen usage:\n"
	       "\t -i: path to hpio device\n"
	       "\t -m: ppktgen mode (rx|tx)\n"
	       "\t -t: tstamp mode (none|hw|sw), default is none\n"
	       "\t -o: packet i/o mode (hpio|raw|udp), default is hpio\n"
	       "\t -p: per CPU rx for udp i/o (on|off), default is on\n"
	       "\t -a: print pps stat on each CPU\n"
	       "\t -d: destination IPv4 address\n"
	       "\t -s: source IPv4 address\n"
	       "\t -D: destination MAC address\n"
	       "\t -S: source MAC address\n"
	       "\t -l: length of a packet\n"
	       "\t -M: CPU mask (hex)\n"
	       "\t -n: number of threads\n"
	       "\t -b: number of bulked packets\n"
	       "\t -c: number of executing writev() on each cpu\n"
	       "\t -I: packet transmit interval (usec)\n"
	       "\t -T: timeout (sec)\n"
		);
}

int main(int argc, char **argv)
{

	int ch, n, cpu, rc;
	int dmacbuf[ETH_ALEN], smacbuf[ETH_ALEN];
	char *pp_mode_str = NULL, *io_mode_str = "hpio", *ts_mode_str = "none";
	char buf[16];		/* for printing parameters to stdout */
	unsigned long use_cpu = 0, mask;
	struct ppktgen_body ppktgen;

	memset(dmacbuf, 0, sizeof(dmacbuf));
	memset(smacbuf, 0, sizeof(smacbuf));

	memset(&ppktgen, 0, sizeof(ppktgen));
	ppktgen.pp_mode = 0; 
	ppktgen.io_mode = IO_MODE_HPIO;
	ppktgen.ts_mode = TS_MODE_NONE;
	ppktgen.ncpus = count_online_cpus();
	ppktgen.nthreads = 1;
	ppktgen.bulk = 1;
	ppktgen.len = 60;
	ppktgen.udp_dst = htons(UDP_DST_PORT);
	ppktgen.udp_src = htons(UDP_SRC_PORT);
	ppktgen.per_cpu_rx = true;

	while ((ch = getopt(argc, argv, "i:m:o:t:p:ad:s:D:S:l:M:n:b:c:I:T:"))
	       != -1) {
		switch (ch) {
		case 'i' :
			/* hpio device path */
			ppktgen.devpath = optarg;
			break;

		case 'm' :
			pp_mode_str = optarg;
			if (strncmp(optarg, "rx", 2) == 0)
				ppktgen.pp_mode = PP_MODE_RX;
			else if (strncmp(optarg, "tx", 2) == 0)
				ppktgen.pp_mode = PP_MODE_TX;
			else {
				pr_err("invalid ppktgen mode '%s'\n", optarg);
				return -1;
			}
			break;

		case 'o' :
			io_mode_str = optarg;
			if (strncmp(optarg, "hpio", 4) == 0)
				ppktgen.io_mode = IO_MODE_HPIO;
			else if (strncmp(optarg, "raw", 3) == 0)
				ppktgen.io_mode = IO_MODE_RAW;
			else if (strncmp(optarg, "udp", 3) == 0)
				ppktgen.io_mode = IO_MODE_UDP;
			else {
				pr_err("invalid i/o mode '%s'\n", optarg);
				return -1;
			}
			break;

		case 't' :
			ts_mode_str = optarg;
			if (strncmp(optarg, "none", 4) == 0)
				ppktgen.ts_mode = TS_MODE_NONE;
			else if (strncmp(optarg, "hw", 2) == 0)
				ppktgen.ts_mode = TS_MODE_HW;
			else if (strncmp(optarg, "sw", 2) == 0)
				ppktgen.ts_mode = TS_MODE_SW;
			else {
				pr_err("invalid tstmap mode '%s'\n", optarg);
				return -1;
			}
			break;

		case 'p' :
			if (strncmp(optarg, "on", 2) == 0)
				ppktgen.per_cpu_rx = true;
			else if (strncmp(optarg, "off", 3) == 0)
				ppktgen.per_cpu_rx = false;
			else {
				pr_err("invalid per_cpu_rx mode '%s'", optarg);
				return -1;
			}
			break;

		case 'a' :
			ppktgen.print_all_cpu_pps = 1;
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
			if (ppktgen.len < 60 || ppktgen.len > MAX_PKTLEN) {
				pr_err("pkt len must be >= 64, < %d\n",
				       MAX_PKTLEN);
				return -1;
			}
			break;

		case 'M' :
			/* CPU mask to specify CPUs to run threads */
			rc = sscanf(optarg, "%lx", &use_cpu);
			if (rc < 1) {
				pr_err("invalid cpu mask %s\n", optarg);
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

		case 'I' :
			/* packet transmit interval */
			ppktgen.interval = atoi(optarg);
			if (ppktgen.interval < -1) {
				pr_err("interval must be > 0\n");
				return -1;
			}
			break;

		case 'T' :
			/* timeout (sec) */
			ppktgen.timeout = atoi(optarg);
			break;

		default:
			usage();
			return -1;
		}
	}

	if (ppktgen.pp_mode == PP_MODE_RX && ppktgen.io_mode == IO_MODE_HPIO) {
		/* In RX mode, ppktgen receives packets on all CPUs
		 * because hpio (currently) can not receive packets to
		 * multiple CPUs (queues) on one CPU.
		 */
		pr_warn("When RX mode with hpio, ppktgen uses all CPUs\n");
		ppktgen.nthreads = ppktgen.ncpus;
	}

	if (ppktgen.pp_mode == PP_MODE_RX && ppktgen.io_mode == IO_MODE_RAW) {
		pr_warn("When RX mode with raw, one rx thread is allowed\n");
		ppktgen.nthreads = 1;
	}

	if (ppktgen.pp_mode == PP_MODE_RX && ppktgen.io_mode == IO_MODE_UDP) {
		if (ppktgen.per_cpu_rx) {
			pr_warn("When RX mode with udp, "
				"and per_cpu_rx is on, all CPUs are used\n");
			ppktgen.nthreads = ppktgen.ncpus;
		} else {
			pr_warn("When RX mode with udp, "
				"and per_cpu_rx if off, only 1 cpu is used\n");
			ppktgen.nthreads = 1;
		}
	}

	if (ppktgen.io_mode == IO_MODE_RAW || ppktgen.io_mode == IO_MODE_UDP) {
		pr_warn("When raw|udp io mode, bluk size is always 1\n");
		ppktgen.bulk = 1;
	}

	if (ppktgen.ts_mode == TS_MODE_HW && ppktgen.io_mode != IO_MODE_HPIO) {
		pr_err("ts mode 'hw' must be with i/o mode 'hpio'\n");
		return -1;
	}

	/* print parameters */
	pr_info("============ Parameters ============\n");
	pr_info("dev:               %s\n", ppktgen.devpath);
	pr_info("pp_mode            %s\n", pp_mode_str);
	pr_info("io_mode            %s\n", io_mode_str);
	pr_info("ts_mode            %s\n", ts_mode_str);

	pr_info("per_cpu_rx         %s\n", (ppktgen.per_cpu_rx) ? "on" :"off");

	inet_ntop(AF_INET, &ppktgen.dst_ip, buf, sizeof(buf));
	pr_info("dst IP:            %s\n", buf);

	inet_ntop(AF_INET, &ppktgen.src_ip, buf, sizeof(buf));
	pr_info("src IP:            %s\n", buf);

	pr_info("dst MAC:           %02x:%02x:%02x:%02x:%02x:%02x\n",
		dmacbuf[0], dmacbuf[1], dmacbuf[2],
		dmacbuf[3], dmacbuf[4], dmacbuf[5]);

	pr_info("src MAC:           %02x:%02x:%02x:%02x:%02x:%02x\n",
		smacbuf[0], smacbuf[1], smacbuf[2],
		smacbuf[3], smacbuf[4], smacbuf[5]);

	pr_info("packet size:       %d\n", ppktgen.len);
	pr_info("number of bulk:    %d\n", ppktgen.bulk);
	pr_info("number of threads: %d\n", ppktgen.nthreads);
	pr_info("CPU mask:          0x%lx\n", use_cpu);
	pr_info("count of writev(): %lu\n", ppktgen.count);
	pr_info("transmit interval: %d\n", ppktgen.interval);
	pr_info("timeout:           %d\n", ppktgen.timeout);
	pr_info("====================================\n");


	/* create threads */
	mask = 1;
	for (n = 0; n < ppktgen.nthreads; n++) {

		if (use_cpu) {
			/* find next cpu to use */
			while(!(mask & use_cpu)) {
				if (mask == 0) {
					mask = 1;
					continue;
				}
				mask <<= 1;
			}

			/* convert bitmask to cpu number */
			for (cpu = 0; !(mask == (1 << cpu)); cpu++);

			/* in next loop, start at next bit */
			mask <<= 1;
		} else {
			cpu = n;
		}

		ppktgen.pt[n].thn = n;
		ppktgen.pt[n].cpu = cpu;
		ppktgen.pt[n].pbody = &ppktgen;
		ppktgen.pt[n].count = ppktgen.count;
		ppktgen.pt[n].fd = get_socket_fd(&ppktgen, &ppktgen.pt[n]);

		pr_info("Create thread %d on cpu %d\n",
			ppktgen.pt[n].thn, ppktgen.pt[n].cpu);

		switch (ppktgen.pp_mode) {
		case PP_MODE_TX:
			rc = pthread_create(&ppktgen.pt[n].tid, NULL,
					    ppktgen_tx_thread, &ppktgen.pt[n]);
			break;

		case PP_MODE_RX:
			rc = pthread_create(&ppktgen.pt[n].tid, NULL,
					    ppktgen_rx_thread, &ppktgen.pt[n]);
			break;

		default:
			pr_err("invalid ppktgen mode\n");
			return -1;
		}
		if (rc < 0) {
			perror("pthread_create");
			exit(EXIT_FAILURE);
		}
	}

	/* start packet count thread */
	rc = pthread_create(&ppktgen.pkt_count_tid, NULL, ppktgen_count_thread,
			    &ppktgen);
	if (rc < 0) {
		perror("pthread_create");
		exit(EXIT_FAILURE);
	}

	/* set signal */
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		perror("cannot set signal\n");
		exit (EXIT_FAILURE);
	}

	/* thread join */
	for (n = 0; n < ppktgen.nthreads; n++)
		pthread_join(ppktgen.pt[n].tid, NULL);

	pthread_join(ppktgen.pkt_count_tid, NULL);

	return 0;
}
