
hpio
====

The haeena (fast in Japanese) packet I/O, called hpio, is an
alternative high-speed packet I/O framework.

**Advantage**
- Very simple packet I/O API: read() and write() system call families.
- No limitations on NICs.

**Disadvantage**
- Poorer performance than netmap or DPDK.
    - no zero-copy.
    - no optimized packet buffers.



How to transmit packets using hpio is described below.

```c
int fd, ret;
struct iovec pkts[8];
fd = open("/dev/hpio/eth0", O_RDWR);

for(;;) {
        /* ... store hpio hdr and payload to pkts ... */
        ret = writev(fd, pkts, 8);
}
```


Existent high-speed packet I/O frameworks expose preallocated packet
buffers in kernel space to user space by mmap(). This achieve
zero-copy between kernel and user spaces, however, it require new APIs
to manipulate packets on the buffers, instead of familiar APIs such as
socket API. Additionally, special device drivers are required.


In contrast, hpio does not use preallocated packet buffers, therefore,
it does not achieve zero-copy. However, hpio can adopt native system
calls for its packet I/O API and work with native device drivers.


Although hpio involves memory copies on system calls and no
optimizations for device drivers, hpio achieves 10 Gbps wire-rate with
60-byte packets. hpio utilizes *protocol stack* (not entire kernel)
bypass, multicore and mutiqueue NICs, packet batching, and interrupt
mitigation (NAPI).


## How to use

Note that we have tested hpio in Ubuntu 17.04 and Ubuntu 17.10.

```shell-session
$ git clone https://github.com/haeena-family/hpio.git
$ cd hpio
$ make
```

Then, you can insmod kmod/hpio.ko. After insmod, /dev/hpio/NICNAME
characeter devices are created. 




## Contact

upa at haeena.net, sora at haeena.net