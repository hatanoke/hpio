
## Filtering traffic taken to hpio by XDP.


### Tested environment
- 4.13.0-16-generic (ubuntu 17.10)
- iproute2-4.13.0 (manually compiled and installed)
 - ELF support is required.
- bcc-tools 0.5.0-1
 - installed from source https://github.com/iovisor/bcc/blob/master/INSTALL.md
 - Note: before install bcc following the INSTALL.md, `sudo dpkg -r libbpfcc`
- clang 1:4.0-37~exp3ubuntu1 
 - installed from default apt repository


### how to compile and set

```shell-session

# compile
clang -O2 -Wall -target bpf -c xdp.c -o xdp.o

# attach XDP program to device
sudo ip link set dev enp3s0 xdp obj xdp.o 

# detach the program from the device
sudo ip link set dev enp3s0 xdp off

```


This XDP program (xdp.c) rewrites ToS fields of incomming packets if
the packets' destination ports match specified port numbers (see
`dst_ports` in xdp.c ). It changes ToS value to 0xFF. Then, hpio
xdp-aware mode will consume only packets with ToS 0xFF.
