
## Filtering traffic taken to hpio by XDP.


### Tested environment
- 4.13.0-16-generic (ubuntu 17.10)
- iproute2-4.13.0 (manually compiled and installed)
    - ELF support is required.
- clang 1:4.0-37~exp3ubuntu1 
    - installed from default apt repository


### how to compile and set

```shell-session

sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/

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
