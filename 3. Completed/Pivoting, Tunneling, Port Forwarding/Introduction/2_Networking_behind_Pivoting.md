## IP Addressing & NICs
* If a computer on a Network does not have an IP address, it will be assigned in software and usually obtained automatically from a DHCP server
* Common to see computers with statically assigned IP's
	* Servers
	- Routers
	- Switch virtual interfaces
	- Printers
	- And any devices that are providing critical services to the network
- Whether assigned `dynamically` or `statically`, the IP address is assigned to a `Network Interface Controller` (`NIC`)
- Commonly, the NIC is referred to as a `Network Interface Card` or `Network Adapter`
- A computer can have multiple NICs (physical and virtual), meaning it can have multiple IP addresses assigned, allowing it to communicate on various networks
- Identifying pivoting opportunities will often depend on the specific IPs assigned to the hosts we compromise because they can indicate what compromised hosts can reach
- This is why it is important for us to always check for additional NICs using commands like `ifconfig` (in macOS and Linux) and `ipconfig` (in Windows)#

```sh
ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 134.122.100.200  netmask 255.255.240.0  broadcast 134.122.111.255
        inet6 fe80::e973:b08d:7bdf:dc67  prefixlen 64  scopeid 0x20<link>
        ether 12:ed:13:35:68:f5  txqueuelen 1000  (Ethernet)
        RX packets 8844  bytes 803773 (784.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5698  bytes 9713896 (9.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.106.0.172  netmask 255.255.240.0  broadcast 10.106.15.255
        inet6 fe80::a5bf:1cd4:9bca:b3ae  prefixlen 64  scopeid 0x20<link>
        ether 4e:c7:60:b0:01:8d  txqueuelen 1000  (Ethernet)
        RX packets 15  bytes 1620 (1.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 1858 (1.8 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 19787  bytes 10346966 (9.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19787  bytes 10346966 (9.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.15.54  netmask 255.255.254.0  destination 10.10.15.54
        inet6 fe80::c85a:5717:5e3a:38de  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef:2::1034  prefixlen 64  scopeid 0x0<global>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7  bytes 336 (336.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

* In the output above, each NIC has an identifier (`eth0`, `eth1`, `lo`, `tun0`) followed by addressing information and traffic statistics
* The tunnel interface (tun0) indicates a VPN connection is active
* The VPN encrypts traffic and also establishes a tunnel over a public network (often the Internet), through `NAT` on a public-facing network appliance, and into the internal/private network
* Also, notice the IP addresses assigned to each NIC
* The IP assigned to eth0 (`134.122.100.200`) is a publicly routable IP address which means ISPs will route traffic originating from this IP over the Internet
* We will see public IPs on devices that are directly facing the Internet, commonly hosted in DMZs
* The other NICs have private IP addresses, which are routable within internal networks but not over the public Internet
* Anyone that wants to communicate over the Internet must have at least one public IP address assigned to an interface on the network appliance that connects to the physical infrastructure connecting to the Internet
* Recall that `NAT` is commonly used to translate private IP addresses to public IP addresses

#### Using ipconfig

```powershell
ipconfig

Windows IP Configuration

Unknown adapter NordLynx:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::1a9
   IPv6 Address. . . . . . . . . . . : dead:beef::f58b:6381:c648:1fb0
   Temporary IPv6 Address. . . . . . : dead:beef::dd0b:7cda:7118:3373
   Link-local IPv6 Address . . . . . : fe80::f58b:6381:c648:1fb0%8
   IPv4 Address. . . . . . . . . . . : 10.129.221.36
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:df81%8
                                       10.129.0.1

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```

* We can see that this system has multiple adapters, but only one of them has IP addresses assigned
* There are [IPv6](https://www.cisco.com/c/en/us/solutions/ipv6/overview.html) addresses and an [IPv4](https://en.wikipedia.org/wiki/IPv4) address
* We will notice some adapters, like the one in the output above, will have an IPv4 and an IPv6 address assigned in a [dual-stack configuration](https://www.cisco.com/c/dam/en_us/solutions/industries/docs/gov/IPV6at_a_glance_c45-625859.pdf) allowing resources to be reached over IPv4 or IPv6
* Every IPv4 address will have a corresponding `subnet mask`
* Defines the `network` & `host` portion of an IP address
* When network traffic is destined for an IP address located in a different network, the computer will send the traffic to its assigned `default gateway`
* Default gateway is usually the IP address assigned to a NIC on an appliance acting as the router for a given LAN
* In the context of pivoting, we need to be mindful of what networks a host we land on can reach, so documenting as much IP addressing information as possible on an engagement can prove helpful

## Routing
* We may need to route traffic to another network by creating a pivot host 
* One way we will see this is through the use of AutoRoute, which allows our attack box to have `routes` to target networks that are reachable through a pivot host
* One key defining characteristic of a router is that it has a routing table that it uses to forward traffic based on the destination IP address

#### Routing Table example

```sh
netstat -r / ip route

Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
default         178.62.64.1     0.0.0.0         UG        0 0          0 eth0
10.10.10.0      10.10.14.1      255.255.254.0   UG        0 0          0 tun0
10.10.14.0      0.0.0.0         255.255.254.0   U         0 0          0 tun0
10.106.0.0      0.0.0.0         255.255.240.0   U         0 0          0 eth1
10.129.0.0      10.10.14.1      255.255.0.0     UG        0 0          0 tun0
178.62.64.0     0.0.0.0         255.255.192.0   U         0 0          0 eth0
```
