#ifndef _HPIO_H_
#define _HPIO_H_

#define HPIO_PACKET_SIZE	2048	/* max size of a packet */
#define HPIO_SLOT_NUM		1024	/* length of a ring */


struct hpio_hdr {
	uint16_t        pktlen;
	uint64_t        tstamp;
} __attribute__ ((__packed__));


struct hpio_slot {
	struct hpio_hdr hdr;
	char pkt[1];
} __attribute__ ((__packed__));



#endif
