* `X-Frame-Options`
	* Check if set otherwise Clickjacking possible
- `Content-Security-Policy`
	- Check [CSP](https://csp-evaluator.withgoogle.com/)
	* Check if e.g `*.amazon.com` is allowed which an Attacker could control
		* Creat subdomain e.g AWS Bucket `xyz.amazonaws.com` 
		* Host webserver with js content `alert('Hello World')`
* `Strict-Transport-Security` (HSTS)
	* Check if set
* `Host`
	* Check what happens when changing to an arbitary Host
	* Check what happens when using original host but change e.g `.com` to `.net`
	* Check what happens when changing to `localhost`
	* Check if server does a DNS lookup on given domain
	* Check for flawed validation
	* Check for ambigous requests
		* Inject duplicate Host header
	* Check what happens when supplying an absolute url + host
	* Check what heppens when supplying line wrapping
	* Check for inject override headers (**param miner**)
		* `X-Forwarded-Host` 
		* `X-Host` 
		* etc.
	* Check for chache poisoning via the host header
	* Check for basic SQLi in the host header
	* Try Bruteforceing interal IP's `192.168.0.0/24`
	* Connection state attack
		* Change change or add header `Connection: keep-alive`
		* Duplicate the request to `/`
		* Create a group with both tabs in Burp
		* Set mode to send group in sequence (single connection)
		* Set the second tab to e.g `/admin` and host `192.168.0.1`
	* Try adding a `@` infront of the `GET` request
		* `GET @private-intranet/example`
* `Access-Control-X` (CORS)
	* Check if  `Origin: pwn.de` is reflected in response `Allow-Origin`
		* Check if `Allow-Credentials: true`
	* Check if `Origin: null` is reflected in response `Allow-Origin`
		* Check if `Allow-Credentials: true`
	* Check if `XSS` is available on subdomain to run CORS