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
	* Check what happens when changing to `localhost`
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