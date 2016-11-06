TARGET = mgdump

CFLAGS = -Wall -O2 $(readv_$(READV)) $(pcap_$(PCAP))
LDFLAGS= -pthread
CC=gcc

READV?=no
readv_yes= -DREADV
readv_no=

PCAP?=yes
pcap_yes= -DPCAP
pcap_no=

SRCS := mgdump.c
OBJS = $(subst .c,.o,$(SRCS))

${TARGET}: ${OBJS}
	$(CC) ${LDFLAGS} -o $@ $^

.c.o:
	$(CC) ${CFLAGS} -o $@ -c $<

.PHONY: clean
clean:
	rm -f ${TARGET} ${OBJS}

