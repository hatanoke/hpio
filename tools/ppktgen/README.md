
**ppktgen: posix syscall packet generator using hpio**

```bash
$ make
gcc -Wall -O2 -o ppktgen.o -c ppktgen.c
gcc -pthread -o ppktgen ppktgen.o
$ ./pktgen -h
./ppktgen: invalid option -- 'h'
ppktgen usage:
	 -i: path to hpio device
	 -d: destination IPv4 address
	 -s: source IPv4 address
	 -D: destination MAC address
	 -S: source MAC address
	 -l: length of a packet
	 -n: number of threads
	 -b: number of bulked packets
	 -t: packet transmit interval (usec)
$


$ # execute ppktgen
$ sudo ./ppktgen -i /dev/hpio/enp0s3 -d 192.168.2.2 -s 10.0.2.15 -D 52:54:00:12:35:02 -S 08:00:27:14:46:98 -b 128 -n 2
main: ============ Parameters ============
main: dev:               /dev/hpio/enp0s3
main: dst IP:            192.168.2.2
main: src IP:            10.0.2.15
main: dst MAC:           52:00:00:12:35:02
main: src MAC:           08:27:27:14:46:98
main: packet size:       64
main: number of bulk:    128
main: number of threads: 2
main: transmit interval: 0
main: ====================================
ppktgen_thread: start to writev() packets on cpu 1
ppktgen_thread: start to writev() packets on cpu 0


$ # you can see transmitted packets with tcpdump simultaneously with ppktgen
$ sudo tcpdump -eni enp0s3 
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on enp0s3, link-type EN10MB (Ethernet), capture size 262144 bytes
06:06:04.500255 08:00:27:14:46:98 > 52:54:00:12:35:02, ethertype IPv4 (0x0800), length 64: 10.0.2.15.60001 > 192.168.2.2.60000: UDP, length 22
06:06:04.500341 08:00:27:14:46:98 > 52:54:00:12:35:02, ethertype IPv4 (0x0800), length 64: 10.0.2.15.60001 > 192.168.2.2.60000: UDP, length 22
06:06:04.500372 08:00:27:14:46:98 > 52:54:00:12:35:02, ethertype IPv4 (0x0800), length 64: 10.0.2.15.60001 > 192.168.2.2.60000: UDP, length 22
...

```
