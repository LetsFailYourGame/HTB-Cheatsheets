### Virtual Hosts
* A `vHost` is a feature that allows several websites to be hosted on a single server
* There are two ways to configure virtual hosts:
	- `IP`-based virtual hosting
	- `Name`-based virtual hosting

### IP-based Virtual Hosting
* A host can have multiple network interfaces
* Multiple IP addresses, or interface aliases, can be configured on each network interface of a host
* The servers or virtual servers running on the host can bind to one or more IP addresses
	* Different servers can be addressed under different IP's on this host
* From the client's point of view, the servers are independent of each other

### Name-based Virtual Hosting
* Several domain names, such as `admin.inlanefreight.htb` and `backup.inlanefreight.htb`, can refer to the same IP
* Internally on the server, these are separated and distinguished using different folders
	* On a Linux server, the vHost `admin.inlanefreight.htb` could point to the folder `/var/www/admin` for example
	* For `backup.inlanefreight.htb` the folder name would then be adapted and could look something like `/var/www/backup`
* Imagine we have identified a web server at `192.168.10.10`

```sh
$ curl -s http://192.168.10.10

<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

* Let's make a `cURL` request sending a domain previously identified during the information gathering in the `HOST` header

```sh
$ curl -s http://192.168.10.10 -H "Host: randomtarget.com"

<html>
    <head>
        <title>Welcome to randomtarget.com!</title>
    </head>
    <body>
        <h1>Success! The randomtarget.com server block is working!</h1>
    </body>
</html>
```

* Now we can automate this by using a dictionary file of possible vhost names and examining the Content-Length header to look for any differences

```sh
app
blog
dev-admin
forum
help
m
my
shop
some
store
support
www
```

### vHost Fuzzing
```sh
$ cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done


********
FUZZING: app
********
Content-Length: 612

********
FUZZING: blog
********
Content-Length: 612

********
FUZZING: dev-admin
********
Content-Length: 120

<SNIP>
```

* We have successfully identified a virtual host called `dev-admin`

```sh
$ curl -s http://192.168.10.10 -H "Host: dev-admin.randomtarget.com"

<!DOCTYPE html>
<html>
<body>

<h1>Randomtarget.com Admin Website</h1>

<p>You shouldn't be here!</p>

</body>
</html>
```

### Automating Virtual Hosts Discovery
```sh
$ ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.10.10
 :: Wordlist         : FUZZ: ./vhosts
 :: Header           : Host: FUZZ.randomtarget.com
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 612
________________________________________________

dev-admin               [Status: 200, Size: 120, Words: 7, Lines: 12]
www                     [Status: 200, Size: 185, Words: 41, Lines: 9]
some                    [Status: 200, Size: 195, Words: 41, Lines: 9]
:: Progress: [12/12] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```