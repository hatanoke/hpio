
hpio
====

The haeena (this means *fast* in Japanese) packet I/O, called hpio, is
an alternative fast packet I/O framework.

**Advantage**
- Very simple packet I/O API: read() and write() system call families.
- No limitations on NICs.

**Disadvantage**
- Poorer performance than netmap or DPDK.
    - no zero-copy.
    - no optimized packet buffers.



This examples shows how to transmit packets using hpio.
```c
int fd, n;
struct iovec iov[BURST];

struct slot {
        struct hpio_hdr hdr;
        char pkt[PKTSIZE];
} slot = { { HPIO_HDR_VERSION, sizeof(struct hpio_hdr), PKTSIZE } };

build_packet(slot.pkt);

for(n = 0; n < BURST; n++) {
        iov[n].iov_base = &slot;
        iov[n].iov_len = sizeof(slot);
}

fd = open("/dev/hpio/eth0", O_RDWR);

for(;;) {
        writev(fd, iov, BURST);
}
```


Recent high-speed packet I/O frameworks expose pre-allocated packet
buffers in kernel space to user space by mmap(). This achieves
zero-copy between kernel and user spaces, however, it requires new
APIs to manipulate packets on the framework-specific buffers, instead
of familiar APIs such as the socket API. Additionally, special device
drivers are required, and it causes the limitaios on NIC choices.


In contrast, hpio does not use pre-allocated packet buffers and
mmap(), therefore, it cannot achieve zero-copy. However, hpio can
adapt native system calls for its packet I/O API and work with native
device drivers.


Although hpio involves memory copies on system calls and no
optimizations for device drivers, hpio achieves 10 Gbps wire-rate with
60-byte packets. hpio utilizes *protocol stack* (not entire kernel)
bypass, multicore and mutiqueue NICs, packet batching, and interrupt
mitigation (NAPI).


## How to use

Note that we have tested hpio in Ubuntu 17.04 and Ubuntu 17.10.

```shell-session
$ git clone https://github.com/hatanoke/hpio.git
$ cd hpio
$ make
```

Then, you can insmod kmod/hpio.ko. After insmod, /dev/hpio/NICNAME
characeter devices are created. tools/ppktgen is an example
application. It is a simple traffic generator application like netmap
pkt-gen and DPDK pktgen.



## Contact

{upa|sora} at haeena.net