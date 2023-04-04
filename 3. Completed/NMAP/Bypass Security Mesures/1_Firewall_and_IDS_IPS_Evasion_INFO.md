### Firewalls
* Security measure against unauthorized connection attempts from external networks
* Software checks whether individual network packets are being passed, ignored, or blocked
* Prevent unwanted connections that could be potentially dangerous

### IDS/IPS
* Intrusion detection system (`IDS`)
* Like the firewall
* Analyses the network for potential attacks, and reports any detected attacks
* `IPS` complements `IDS` by taking specific defensive measures if a potential attack is detected
* Analysis based on pattern matching and signatures

#### Determine Firewalls and Their Rules
* Multiple reasons for filtered ports
* Most cases firewall block
	* Dropped or rejected
	* Dropped packets are ignored, and no response is returned
	* Rejected return with an `RST` flag
		* Contain different types of ICMP error codes or contain nothing at all
			-   Net Unreachable
			-   Net Prohibited
			-   Host Unreachable
			-   Host Prohibited
			-   Port Unreachable
			-   Proto Unreachable
- NMAP's TCP ACK scan `-sA` method is much harder to filter for firewalls and IDS/IPS than regular SYN `-sS` or Connect scans `sT` 
	- Only send a TCP packet with only the `ACK` flag
- When a port is closed or open
	- Host must respond with an `RST` flag
- Unlike outgoing connections, all connections attempts (with `SYN` flag) from external networks are usually blocked by firewalls
- However the packets with `ACK` flags are often passed by firewall because the firewall cannot determine whether the connection was first established from the external network or the internal network

#### SYN-Scan
```sh
$ sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 14:56 CEST
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:22 S ttl=53 id=22412 iplen=44  seq=4092255222 win=1024 <mss 1460>
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:25 S ttl=50 id=62291 iplen=44  seq=4092255222 win=1024 <mss 1460>
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:21 S ttl=58 id=38696 iplen=44  seq=4092255222 win=1024 <mss 1460>
RCVD (0.0329s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=40884 iplen=72 ]
RCVD (0.0341s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
RCVD (1.0386s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
SENT (1.1366s) TCP 10.10.14.2:57348 > 10.129.2.28:25 S ttl=44 id=6796 iplen=44  seq=4092320759 win=1024 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.0053s latency).

PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp open     ssh
25/tcp filtered smtp
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
```

#### ACK-Scan
```sh
$ sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 14:57 CEST
SENT (0.0422s) TCP 10.10.14.2:49343 > 10.129.2.28:21 A ttl=49 id=12381 iplen=40  seq=0 win=1024
SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:22 A ttl=41 id=5146 iplen=40  seq=0 win=1024
SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:25 A ttl=49 id=5800 iplen=40  seq=0 win=1024
RCVD (0.1252s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=55628 iplen=68 ]
RCVD (0.1268s) TCP 10.129.2.28:22 > 10.10.14.2:49343 R ttl=64 id=0 iplen=40  seq=1660784500 win=0
SENT (1.3837s) TCP 10.10.14.2:49344 > 10.129.2.28:25 A ttl=59 id=21915 iplen=40  seq=0 win=1024
Nmap scan report for 10.129.2.28
Host is up (0.083s latency).

PORT   STATE      SERVICE
21/tcp filtered   ftp
22/tcp unfiltered ssh
25/tcp filtered   smtp
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
```

* Pay attention to the RCVD packets and its set flag we receive from our target
* With SYN scan `-sS` target tries to establish the TCP connection by sending a packet back with the SYN-ACK (`SA`) flags set and with the ACK scan (`-sA`) we get the `RST` flag because TCP port 22 is open
* Since we don't receive any packets back for port 25, the packets must be dropped

### Detect IDS/IPS
* Detection of IDS/IPS systems much more difficult became they are passive monitors
* `IDS` systems examine all connections between hosts
* If IDS finds packets containing defined contents or specification, admin is notified
* IDS and IPS are different applications and IPS serves as a complement to IDS
* First step to defend in such an attack is to ban the IP
	* We will no longer be able to access the network
	* ISP will be contacted and blocked from all access to the Internet
* **IDS** systems alone usually help administrators detect potential attacks
	* They can decide how to handle such connections
* One method to determine whether such **IPS** system is present
	* Scan a single host virtual private server (**VPS**)
		* If at any time this host is blocked and has no access to the target network
		* Administrator has taken some security measures
		* We can continue the penetration test with another **VPS**

### Decoys
* There are cases in which administrators block specific subnets from different regions
* Prevents any access to target network
* Decoy scanning method (`-D`) is the right choice then
	* Nmap generates various random IP addresses inserted into the IP header
		* Disguise the origin of the packets sent
	* We can generate random (`RND`) a specific number (e.g `5`) of IP addresses
		* Separated by a colon (`:`)
	* Our real IP is placed randomly in between the generated IPs
	* A critical point is that the decoys must be alive
		* Otherwise service on target may be unreachable due to SYN-flooding security mechanisms

```sh
$ sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 16:14 CEST
SENT (0.0378s) TCP 102.52.161.59:59289 > 10.129.2.28:80 S ttl=42 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0378s) TCP 10.10.14.2:59289 > 10.129.2.28:80 S ttl=59 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 210.120.38.29:59289 > 10.129.2.28:80 S ttl=37 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 191.6.64.171:59289 > 10.129.2.28:80 S ttl=38 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 184.178.194.209:59289 > 10.129.2.28:80 S ttl=39 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 43.21.121.33:59289 > 10.129.2.28:80 S ttl=55 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
RCVD (0.1370s) TCP 10.129.2.28:80 > 10.10.14.2:59289 SA ttl=64 id=0 iplen=44  seq=4056111701 win=64240 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.099s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
```

* Spoofed packets, often filtered by ISPs and routers
* Specify our VPS servers' IP addresses and use them in combination with `IP ID` manipulation in the IP headers to scan the target
* Another scenario would be that only individual subnets would not have access to the server's specific services
	* Manually specify the source IP address (`-S`) to test if we get better results with this one
* Decoys can be used for SYN, ACK, ICMP scans, and OS detection scans

#### Testing Firewall Rule
```sh
$ sudo nmap 10.129.2.28 -n -Pn -p445 -O

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 01:23 CEST
Nmap scan report for 10.129.2.28
Host is up (0.032s latency).

PORT    STATE    SERVICE
445/tcp filtered microsoft-ds
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop
```

#### Scan by Using Different Source IP
```sh
$ sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 01:16 CEST
Nmap scan report for 10.129.2.28
Host is up (0.010s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Linux 2.6.32 - 2.6.35 (94%), Linux 2.6.32 - 3.5 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
```

### DNS Proxying
* By default, NMAP performs reverse DNS resolution unless otherwise specified
	* Most cases passed by given web server
	* DNS queries are made over `UDP port 53`
	* `TCP port 53` previously used for `Zone-transfers` but is slowly changing due to IPv6 and DNSSEC, so many DNS requests are made over TCP port 53
* Specify DNS server `--dns-server <ns>,<ns>`
	* Fundamental if we are in a `DMZ` 
	* Company's DNS server are usually more trusted than those from the internet
	* We could use them to interact with the hosts of the internal network
* Another example is to use `TCP port 53` as a source port (`--source-port`) for our scans
	* If administrator uses firewall to control this port and does not filter IDS/IPS properly
	* TCP packets will be trusted and pass through

#### SYN-Scan of a Filtered Port
```sh
$ sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 22:50 CEST
SENT (0.0417s) TCP 10.10.14.2:33436 > 10.129.2.28:50000 S ttl=41 id=21939 iplen=44  seq=736533153 win=1024 <mss 1460>
SENT (1.0481s) TCP 10.10.14.2:33437 > 10.129.2.28:50000 S ttl=46 id=6446 iplen=44  seq=736598688 win=1024 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up.

PORT      STATE    SERVICE
50000/tcp filtered ibm-db2
```

#### SYN-Scan From DNS Port
```sh
$ sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

SENT (0.0482s) TCP 10.10.14.2:53 > 10.129.2.28:50000 S ttl=58 id=27470 iplen=44  seq=4003923435 win=1024 <mss 1460>
RCVD (0.0608s) TCP 10.129.2.28:50000 > 10.10.14.2:53 SA ttl=64 id=0 iplen=44  seq=540635485 win=64240 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.013s latency).

PORT      STATE SERVICE
50000/tcp open  ibm-db2
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
```

* We can see that `TCP port 53` is passed through the firewall
* Very likely that IDS/IPS filters might also be configured much weaker than others
* We can test this by trying to connect to this port using `Netcat`

```sh
$ ncat -nv --source-port 53 10.129.2.28 50000

Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.2.28:50000.
220 ProFTPd
```