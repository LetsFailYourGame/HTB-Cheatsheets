### Shell types
| Shell Type    | Description                                                                                                                                                                                                                                       |     |     |     |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | --- | --- |
| Reverse shell | Initiates a connection back to a "listener" on our attack box.                                                                                                                                                                                    |     |     |     |
| Bind shell    | "Binds" to a specific port on the target host and waits for a connection from our attack box.                                                                                                                                                     |     |     |     |
| Web shell     | Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a `PHP` script to run a single command. |     |     |     |

### What is a Port?
* Like a window or door on a house 
	* If not secured (Window or door is open) we can gain unauthorized access
* Ports are virtual points where network connections begin and end
	* Software-based
	* Managed by host OS
* Has an assigned number
	* HTTP 80 for example
* Transmission Control Protocol (`TCP`)
	* Connection-oriented
	* Server in listening state awaiting connection requests from client
* User Datagram Protocol (`UDP`)
	*  connectionless
	* No “handshake”
	* Useful when error detection is not needed (Videos for example)
* 65535 different Ports available

#### Some [well-known](https://packetlife.net/media/library/23/common-ports.pdf) ports
| Port(s)         | Protocol        |
| --------------- | --------------- |
| `20`/`21` (TCP) | FTP             |
| `22` (TCP)      | SSH             |
| `23` (TCP)      | Telnet          |
| `25` (TCP)      | SMTP            |
| `80` (TCP)      | HTTP            |
| `161` (TCP/UDP) | SNMP            |
| `389` (TCP/UDP) | LDAP            |
| `443` (TCP)     | SSL/TLS (HTTPS) |
| `445` (TCP)     | SMB             |
| `3389` (TCP)    | RDPP            |

### What is a Web server
* Application that runs on the back-end server
* Usually run on TCP ports `80` or `443`
* Handles all HTTP traffic from client-side browser → server
* If suffering from vulnerabilities back-end server can be compromised 
* Top 10 OWASP vulnerabilities
	* ![[Pasted image 20220913171642.png]]