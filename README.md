# Useful Commands (General)
| **Command**                          | **Description**                                |
| ------------------------------------ | ---------------------------------------------- |
| `locate <path>`                      | Find files in any directory                    |
| `ssh-keygen -t rsa`                  | Generate key pair (SSH)                        |
| `which <programm_name>`              | Finds the path to a given program if it exists |



# Useful Commands (NMAP)
| Command                                            | Description                                              |
| -------------------------------------------------- | -------------------------------------------------------- |
| `tcpdump -i tun0 host <host_ip>`                   | Can display additional information nmap doesn't show     |
| `nmap <host_ip> -Pn -n -disable-arp-ping -sV -sS ` | Stealth nmap scan which enumerates service versions      |
| `nmap --source-port <port>`                        | Can bypass miss configured firewalls by imitating a port |
| `xsltproc <xml_file> -o <html_file>`               | Export nmap scan to HTML file                            |





