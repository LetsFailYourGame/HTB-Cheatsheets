### Service Version Detection
* Recommended to do a quick port scan first to give an overview of all available ports
* Use `-sV` to enumerate services and their version
* Show NMAP stats by pressing SPACE or provide the `--stats-every=5s` flag
* Use the `-v` option to print verbose output

```bash
$ sudo nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-16 20:10 CEST
<SNIP>
NSOCK INFO [0.4200s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 18 [10.129.2.28:25] (35 bytes): 220 inlane ESMTP Postfix (Ubuntu)..
Service scan match (Probe NULL matched with NULL line 3104): 10.129.2.28:25 is smtp.  Version: |Postfix smtpd|||
NSOCK INFO [0.4200s] nsock_iod_delete(): nsock_iod_delete (IOD #1)
Nmap scan report for 10.129.2.28
Host is up (0.076s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Service Info: Host:  inlane

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
```

* Sometimes NMAP doesn't display all information
	* `[10.129.2.28:25] (35 bytes): 220 inlane ESMTP Postfix (Ubuntu)`
	* Shows that it is an Ubuntu system which is not displayed in the output
		* This comes because NMAP sometimes doesn't know how to handle output
* We can manually connect and check out the banner with `tcpdump` and `netcat`

```bash
$ sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
```

```bash
$  nc -nv 10.129.2.28 25
```

```bash
18:28:07.128564 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [S], seq 1798872233, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 331260178 ecr 0,sackOK,eol], length 0
18:28:07.255151 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [S.], seq 1130574379, ack 1798872234, win 65160, options [mss 1460,sackOK,TS val 1800383922 ecr 331260178,nop,wscale 7], length 0
18:28:07.255281 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 1, win 2058, options [nop,nop,TS val 331260304 ecr 1800383922], length 0
18:28:07.319306 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [P.], seq 1:36, ack 1, win 510, options [nop,nop,TS val 1800383985 ecr 331260304], length 35: SMTP: 220 inlane ESMTP Postfix (Ubuntu)
18:28:07.319426 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 36, win 2058, options [nop,nop,TS val 331260368 ecr 1800383985], length 0
```

* The first three lines show us the three-way handshake

```bash
[SYN] 18:28:07.128564 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [S] <SNIP>
[SYN-ACK] 18:28:07.255151 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [S.] <SNIP>
[ACK] 18:28:07.255281 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.] <SNIP>
```

* After that, the target SMTP server sends us a TCP packet with the `PSH` and `ACK` flags, where `PSH` states that the target server is sending data to us and with `ACK` simultaneously informs us that all required data has been sent.

```bash
[PSH-ACK] 18:28:07.319306 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [P.] <SNIP>
```

* The last TCP packet that we sent confirms the receipt of the data with an `ACK`

```bash
[ACK] 18:28:07.319426 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.] <SNIP>
```