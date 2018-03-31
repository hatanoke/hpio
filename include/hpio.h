#ifndef _HPIO_H_
#define _HPIO_H_

#define HPIO_PACKET_SIZE	2048	/* max size of a packet */
#define HPIO_SLOT_NUM		1024	/* length of a ring */


#define HPIO_HDR_VERSION	0x02

struct hpio_hdr {
	uint8_t 	version;
	uint8_t		hdrlen;		/* hpio_hdr length */
	uint16_t        pktlen;		/* byte length of pkt trailing hdr */

	uint64_t        tstamp;		/* hw timestamp */
} __attribute__ ((__packed__));



/* HPIO as socket address family */
#define PF_HPIO		PF_IPX
#define AF_HPIO		PF_HPIO

#endif
