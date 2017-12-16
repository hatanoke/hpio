/* enable/disable hw stamp */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>

enum _action {
	SHOW,
	SET,
};

struct param {
	int action;

	char ifname[IFNAMSIZ];
	int tx_type;
	int rx_filter;
};

void show(struct param p)
{
	int sock;
	struct ifreq ifr;
	struct hwtstamp_config config;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, p.ifname, IFNAMSIZ);
	ifr.ifr_data = (caddr_t)&config;

	if (ioctl(sock, SIOCGHWTSTAMP, &ifr)) {
		perror("ioctl");
		return;
	}

	printf("dev %s tx %d rx %d", p.ifname,
	       config.tx_type, config.rx_filter);
}

void set(struct param p)
{
	int sock;
	struct ifreq ifr;
	struct hwtstamp_config config;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return;
	}

	config.flags = 0;
	config.tx_type = p.tx_type;
	config.rx_filter = p.rx_filter;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, p.ifname, IFNAMSIZ);
	ifr.ifr_data = (caddr_t)&config;

	if (ioctl(sock, SIOCSHWTSTAMP, &ifr)) {
		perror("ioctl");
		return;
	}
}

void usage(void)
{
	printf("hwstamp usage:\n"
	       "    show dev IFNAME : display current setting\n"
	       "    set { tx INT } { rx INT } dev IFNAME\n"
		);
}

int main(int argc, char **argv)
{
	int n;
	struct param p;

	memset(&p, 0, sizeof(p));

	for (n = 1; n < argc; n++) {
		if (strncmp(argv[n], "show", 4) == 0)
			p.action = SHOW;
		else if (strncmp(argv[n], "set", 3) == 0)
			p.action = SET;
		else if (strncmp(argv[n], "dev", 3) == 0) {
			strncpy(p.ifname, argv[n + 1], IFNAMSIZ);
			n++;
		} else if (strncmp(argv[n], "tx", 2) == 0) {
			p.tx_type = atoi(argv[n + 1]);
			n++;
		} else if (strncmp(argv[n], "rx", 2) == 0) {
			p.rx_filter = atoi(argv[n + 1]);
			n++;
		} else {
			usage();
			return 1;
		}
	}

	switch (p.action) {
	case SHOW :
		show(p);
		break;
	case SET :
		set(p);
		break;
	}

	return 0;
}
