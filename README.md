# Useful Links
* [IPPSEC](https://ippsec.rocks/?#) search a term, get a detailed video
* Lists of Unix binaries for privesc
	* [LOLBAS](https://lolbas-project.github.io/#/) (Windows)
	* [GTFOBins](https://gtfobins.github.io/) (Linux)
* [HackTricks](https://book.hacktricks.xyz/welcome/readme), for checklists and information

# Useful Commands (General)
| **Command**                                                                                               | **Description**                                |
| --------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `locate <path>`                                                                                           | Find files in any directory                    |
| `ssh-keygen -t rsa`                                                                                       | Generate key pair (SSH)                        |
| `which <programm_name>`                                                                                   | Finds the path to a given program if it exists |
| `openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'` | Create a self-signed certificate               |
| `gunzip -S .zip <file>`                                                                                   | Unzip a file                                   |
| `sudo -l`                                                                                                 | Check missconfigured binarys                   |
| `chmod 600`                                                                                               | Set RSA keys permissions                       |
| `find / -user <user> (-group <group>) (-ls) 2>/dev/null` \| `grep -v '/<dir_to_hide>\|<dir2>'`                  | Grep all the contents owed by user filtered    |
| `searchsploit -x <path>`                                                                                  | Save searchsploit exploit                      |
| `groups`                                                                                                  | Check the groups of a user                                               |

# Useful Commands (NMAP)
| **Command**                                            | **Description**                                              |
| -------------------------------------------------- | -------------------------------------------------------- |
| `tcpdump -i tun0 host <host_ip>`                   | Can display additional information nmap doesn't show     |
| `nmap <host_ip> -Pn -n -disable-arp-ping -sV -sS ` | Stealth nmap scan which enumerates service versions      |
| `nmap --source-port <port>`                        | Can bypass miss configured firewalls by imitating a port |
| `xsltproc <xml_file> -o <html_file>`               | Export nmap scan to HTML file                            |

# Useful Commands (Services)
| **Command**                                                  | **Description**               |
| -------------------------------------------------------- | ------------------------- |
| `nc -nv <ip> <port>`                                     | Interact with a service   |
| `telnet <ip> <port>`                                     | Interact with a service   |
| `ftp <ip>`                                               | Interact with ftp service |
| `xfreerdp /v:10.10.10.132 /d:<dir> /u:<user> /p:<pass> ` | Connect via RDP           | 

