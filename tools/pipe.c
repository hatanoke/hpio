/*
 * read from hpio device A, and write to hpio device B
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>

#include <hpio.h>

#define MAX_CPU	64
#define BULKNUM	128

struct pipe_thread {
	pthread_t	tid;

	char *devpath_r, *devpath_w;
	
	int rd_fd;	/* fd for read from hpio device */
	int wr_fd;	/* fd for write to output file */
	int cpu;	/* cpu number this thread running on */
};


/* global variable */
static int caught_signal = 0;


void sig_handler(int sig) {
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

void usage(char *progname)
{
	printf("%s usage:\n"
	       "\t -r: read hpio device path\n"
	       "\t -w: write hpio device path\n",
		progname);
}

void *pipe_body(void *arg)
{
	/* Read from hpio, Write to file thread body */

	int n, cnt, ret;
	cpu_set_t target_cpu_set;
	struct pipe_thread *pdt = (struct pipe_thread *)arg;
	struct iovec iov[BULKNUM];

	struct hpio_slot {
		struct hpio_hdr hdr;
		char buf[2048];
	} __attribute__ ((__packed__));

	struct hpio_slot slot[BULKNUM];


	/* pin cpu runnign this thread */
	CPU_ZERO(&target_cpu_set);
	CPU_SET(pdt->cpu, &target_cpu_set);
	pthread_setaffinity_np(pdt->tid, sizeof(cpu_set_t), &target_cpu_set);
	printf("thread %d on cpu %d\n", pdt->cpu, sched_getcpu());

	/* initialize packet buffer */
	for (n = 0; n < BULKNUM; n++) {
		iov[n].iov_base = &slot[n];
		iov[n].iov_len = sizeof(struct hpio_slot);
	}
	
	while (1) {
		/* read and write loop */
		if (caught_signal)
			break;

		cnt = readv(pdt->rd_fd, iov, BULKNUM);

		if (cnt < 1) {
			usleep(100);
			continue;
		}

		ret = writev(pdt->wr_fd, iov, cnt);
		if (ret < 0)
			perror("writev");

		printf("read %d pkt from %s, write %d pkt to %s on cpu %d\n",
		       cnt, pdt->devpath_r, ret, pdt->devpath_w, pdt->cpu);
	}

	printf("thread %d finished\n", pdt->cpu);
	close(pdt->rd_fd);
	close(pdt->wr_fd);

	return NULL;
}

int main (int argc, char **argv)
{
	int rd_fd, wr_fd, n, ncpus, ret, ch;
	char *devpath_r, *devpath_w;
	struct pipe_thread pdts[MAX_CPU];

	devpath_r = NULL;
	devpath_w = NULL;

	while ((ch = getopt(argc, argv, "r:w:")) != -1) {
		switch(ch) {
		case 'r' :
			devpath_r = optarg;
			break;
		case 'w' :
			devpath_w = optarg;
			break;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (!devpath_r || !devpath_w) {
		printf("two hpio devices must be specified\n");
		usage(argv[0]);
		return -1;
	}

	ncpus = count_online_cpus();
	ncpus = ncpus < MAX_CPU ? ncpus : MAX_CPU;

	
	/* open read hpio descriptor and dispatch to pipe_thread */
	for (n = 0; n < ncpus; n++) {

		rd_fd = open(devpath_r, O_RDONLY);
		if (rd_fd < 0) {
			fprintf(stderr, "cannot open device %s\n", devpath_r);
			perror("open");
			return -1;
		}

		wr_fd = open(devpath_w, O_WRONLY);
		if (wr_fd < 0) {
			fprintf(stderr, "cannot open device %s\n", devpath_w);
			perror("open");
			return -1;
		}

		pdts[n].rd_fd = rd_fd;
		pdts[n].wr_fd = wr_fd;
		pdts[n].devpath_r = devpath_r;
		pdts[n].devpath_w = devpath_w;
		pdts[n].cpu = n;

		ret = pthread_create(&pdts[n].tid, NULL, pipe_body, &pdts[n]);
		if (ret < 0) {
			perror("pthread_create");
			return -1;
		}
	}


	/* set signal */
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "cannot set signal\n");
		return 0;
	}
	

	// thread join
	for (n = 0; n < ncpus; n++) {
		pthread_join(pdts[n].tid, NULL);
	}

	return 0;
}
