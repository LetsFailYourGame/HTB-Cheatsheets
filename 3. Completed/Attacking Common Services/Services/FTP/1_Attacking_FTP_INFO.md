## Enumeration
* `Nmap` default scripts `-sC` includes the [ftp-anon](https://nmap.org/nsedoc/scripts/ftp-anon.html)
*  `-sV` provides interesting information about FTP services, such as the FTP banner, which often includes the version name
* Use the `ftp` client or `nc` to interact with the FTP service

```bash
 sudo nmap -sC -sV -p 21 192.168.2.142 

Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-10 22:04 EDT
Nmap scan report for 192.168.2.142
Host is up (0.00054s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 1170     924            31 Mar 28  2001 .banner
| d--x--x--x   2 root     root         1024 Jan 14  2002 bin
| d--x--x--x   2 root     root         1024 Aug 10  1999 etc
| drwxr-srwt   2 1170     924          2048 Jul 19 18:48 incoming [NSE: writeable]
| d--x--x--x   2 root     root         1024 Jan 14  2002 lib
| drwxr-sr-x   2 1170     924          1024 Aug  5  2004 pub
|_Only 6 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
```

## Misconfigurations
*  `anonymous` username and no password (Anonymous login)

#### Anonymous Authentication
```bash
ftp 192.168.2.142    
                     
Connected to 192.168.2.142.
220 (vsFTPd 2.3.4)
Name (192.168.2.142:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0               9 Aug 12 16:51 test.txt
226 Directory send OK.
```

* Use `get` for single or `mget` to download multiple files
* For uploads, we can use `put` or `mput` similar

#### Brute Forcing
* If there's no anonymous login we can try to brute-force the login

**Note:** Although we may find services vulnerable to brute force, most applications today prevent these types of attacks. A more effective method is Password Spraying.

#### Brute Forcing with Medusa
```bash
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
                                                             
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>                                                      
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456 (1 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 12345 (2 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456789 (3 of 14344392 complete)
ACCOUNT FOUND: [ftp] Host: 10.129.203.7 User: fiona Password: family [SUCCESS]
```

#### FTP Bounce Attack
* A network attack that uses FTP servers to deliver outbound traffic to another device on the network
* Attacker uses a `PORT` command to trick the FTP connection into running commands and getting information from a device other than the intended server
* Example
	* `FTP_DMZ` exposed to the internet
	* Another device within the same network, `Internal_DMZ`, is not exposed to the internet
	* We can use the connection to the `FTP_DMZ` server to scan `Internal_DMZ` using the FTP Bounce attack and obtain information about the server's open ports
* Use `-b` flag in `Nmap`

```bash
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 04:55 EDT
Resolved FTP bounce attack proxy to 10.10.110.213 (10.10.110.213).
Attempting connection to ftp://anonymous:password@10.10.110.213:21
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
Initiating Bounce Scan at 04:55
FTP command misalignment detected ... correcting.
Completed Bounce Scan at 04:55, 0.54s elapsed (1 total ports)
Nmap scan report for 172.17.0.2
Host is up.

PORT   STATE  SERVICE
80/tcp open http

<SNIP>
```

**Note:** Modern FTP servers include protections that, by default, prevent this type of attack, but if these features are misconfigured in modern-day FTP servers, the server can become vulnerable to an FTP Bounce attack.

