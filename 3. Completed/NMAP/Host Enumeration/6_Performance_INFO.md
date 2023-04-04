### Performance
* We can tell NMAP how fast to go (`-T <1-5>`) 
* Frequency (`--min-parallelism <number>`), and which timeouts (`--max-rtt-timeout <time>`) the packets should have
* How many packets should be sent simultaneously (`--min-rate <number>`), and the number of retries (`--max-retries <number>`) for the scanned ports

### Timeouts
* When packets sent
	* Takes some `RTT` to receive a response
	* Generally NMAP starts with a high timeout (`--min-RTT-timeout`) of 100ms

* Example with 256 hosts, including the top 100 ports

```sh
$ sudo nmap 10.129.2.0/24 -F

<SNIP>
Nmap done: 256 IP addresses (10 hosts up) scanned in 39.44 seconds
```

* After optimizing

```sh
$ sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms

<SNIP>
Nmap done: 256 IP addresses (8 hosts up) scanned in 12.29 seconds
```

* Too short time (`--initial-rtt-timeout`) may cause us to overlook hosts

### Max Retries
* Default value for (`--max-retries`) is 10

#### Default Scan
```sh
$ sudo nmap 10.129.2.0/24 -F | grep "/tcp" | wc -l

23
```

#### Reduced Retries
```sh
$ sudo nmap 10.129.2.0/24 -F --max-retries 0 | grep "/tcp" | wc -l

21
```

* Again, accelerating can have a negative effect on the results

### Rates
* We may get whitelisted in a white-box penetration test
* If we know network bandwidth
	* Change rate of packets sent
	* Significantly speeds up scan

#### Default Scan
```sh
$ sudo nmap 10.129.2.0/24 -F

<SNIP>
Nmap done: 256 IP addresses (10 hosts up) scanned in 29.83 seconds
```

#### Optimized Scan
```sh
$ sudo nmap 10.129.2.0/24 -F --min-rate 300

<SNIP>
Nmap done: 256 IP addresses (10 hosts up) scanned in 8.67 seconds
```

### Timing
-   `-T 0` / `-T paranoid`
-   `-T 1` / `-T sneaky`
-   `-T 2` / `-T polite`
-   `-T 3` / `-T normal`
-   `-T 4` / `-T aggressive`
-   `-T 5` / `-T insane`

#### Default Scan
```shell-session
$ sudo nmap 10.129.2.0/24 -F -oN tnet.default 

<SNIP>
Nmap done: 256 IP addresses (10 hosts up) scanned in 32.44 seconds
```

#### Optimized Scan
```shell-session
$ sudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T 5

<SNIP>
Nmap done: 256 IP addresses (10 hosts up) scanned in 18.07 seconds
```

