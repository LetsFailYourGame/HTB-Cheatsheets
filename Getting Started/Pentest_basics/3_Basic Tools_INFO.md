### Using SSH
* Secure Shell (SSH) 
	* Default port `22`
* Secure way to access a computer remotely
* Password or public-key authentication
* Client-server model
* User uses SSH Client to connect to a server
	* `OpenSSH` for example
* Much more stable than reverse shells

```bash
$ ssh Bob@10.10.10.10
password: *********

Bob@remotehost#
```

### Using Netcat
* `Netcat`, `ncat` or `nc` is a widely used network utility for interacting with TCP/UDP ports
* Many uses
	* `Primary usage:` connecting to shells
	* Can connect to any listening port and interact with the service running on that

```bash
# For example connect via SSH on port 22

$ netcat 10.10.10.10 22

# Returns a banner
SSH-2.0-OpenSSH_8.4p1 Debian-3
```

* We received a `banner` stating that `SSH` is running on that port
	* This technique is called `Banner Grabbing`
		* Helps to identify what service is running on a particular port
