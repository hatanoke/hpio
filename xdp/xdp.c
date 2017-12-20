#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define HPIO_TOS_VALUE 0xFF


/* XXX: How to use ntohs/ntohs in xdp env without bcc? */
#define htons(n) (((n & 0x00FF) << 8) | ((n & 0xFF00) >> 8))
#define ntohs(n) (((n & 0xFF00) >> 8) | ((n & 0x00FF) << 8))



#define ARRAY_SIZE(X) (sizeof(X) / sizeof(X[0]))

#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

static inline __u8 get_ip_protocol(void *pkt, void *end, __u64 offset)
{
	/* offset indicates start of iphdr */
	struct iphdr *ip = pkt + offset;

	if (pkt + offset + sizeof(*ip) > end)
		return 0;

	return ip->protocol;
}

static inline __u16 get_dst_port(void *pkt, void *end, __u64 offset,
				 int protocol)
{
	/* offset indicates start of transport header */
	struct udphdr *udp;
	struct tcphdr *tcp;

	switch(protocol) {
	case IPPROTO_UDP :
		udp = pkt + offset;
		if (pkt + offset + sizeof(*udp) > end)
			return 0;
		return ntohs(udp->dest);

	case IPPROTO_TCP :
		tcp = pkt + offset;
		if (pkt + offset + sizeof(*tcp) > end)
			return 0;
		return ntohs(tcp->dest);
	}

	return 0;
}


static inline __u16 checksum (const void * data, __u16 len, __u32 sum)
{
        __u32 i;
        const __u8 *addr = data;

        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (__u16)ntohs(*((__u16 *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }

        if (i < len) {
                sum += addr[i] << 8;
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }

	return sum;
}


static inline __u16 wrapsum (__u32 sum)
{
        sum = ~sum & 0xFFFF;
        return (htons(sum));
}


static inline void set_tos(void *pkt, void *end, __u64 offset, __u8 tos)
{
	struct iphdr *ip = pkt + offset;
	ip->tos = tos;
	ip->check = 0;
	ip->check = wrapsum(checksum(ip, sizeof(*ip), 0));
}



#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

__section("prog")
int xdp_set_tos(struct xdp_md *ctx)
{
	int n;
	__u8 protocol;
	__u16 h_proto;
	__u16 dst_port;
	__u16 dst_ports[] = { 5004, 5005, 60000, 60001 };

	__u64 offset = 0;
	void *pkt = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = pkt;
	if (pkt + sizeof(*eth) > end)
		return XDP_PASS;
	
	h_proto = eth->h_proto;
	if (h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	offset += sizeof(*eth);
	protocol = get_ip_protocol(pkt, end, offset);
	if (protocol == 0)
		return XDP_PASS;


	offset += sizeof(struct iphdr);
	dst_port = get_dst_port(pkt, end, offset, protocol);
	if (dst_port == 0)
		return XDP_PASS;


	for (n = 0; n < ARRAY_SIZE(dst_ports); n++) {
		if (dst_port == dst_ports[n]) {
			set_tos(pkt, end, offset - sizeof(struct iphdr),
				HPIO_TOS_VALUE);
			return XDP_PASS;
		}
	}
	
	return XDP_PASS;
}

char __license[] __section("license") = "GPL";
