![](Web%20checklist/Screenshots/password-reset-poisoning.svg)
## Password-based login
* Check if unsecured password is used
* Check if usernames can be enumerated
	* Check if usernames / profiles **accessible when not logged in**
	* Check if password reset / login **errors display*** existens
	* Check **HTTP status code** when bruteforcing
	* Check Response time
		* Create a long password and see if correct usernames take longer to process

## Multi-factor Authentication
* Check for **two-factor** bypass
	* Check if two-factor opens on a seperate page which means we are in a logged in stage already and we can try to skip the code
* Check if not **bruteforce protection** is in place
	* Code is often only a 4 Digit number
* Flawed logic

```http
POST /login-steps/first 
HTTP/1.1 Host: vulnerable-website.com ... username=carlos&password=qwerty

# Getting coockie before 2FA
HTTP/1.1 200 OK Set-Cookie: 
account=carlos GET /login-steps/second HTTP/1.1 
Cookie: account=carlos

# Cookie used to determine which account user is trying to access
POST /login-steps/second HTTP/1.1 
Host: vulnerable-website.com 
Cookie: account=carlos 
... 
verification-code=123456

# Change it to something else
POST /login-steps/second 
HTTP/1.1 Host: vulnerable-website.com 
Cookie: account=victim-user 
... 
verification-code=123456
```

## Other Authentication mechanisms
* Check **Coockies** for keep user logged in token
	* If known how the cookie is built, we can bruteforce other users
* Check **code** if opensource
* Check **reset password** option
	* Check how the reset works e.g E-Mail, URL
	* Check for **host header** injection

## oAuth2
- Check **standard endpoints** 
	- `/.well-known/oauth-authorization-server`
	-  `/.well-known/openid-configuration`
	- ``/.well-known/openid-configuration``
	- `/.well-known/jwks.json
		- respone_type=id_token (token/code)
- Check **improper implementation** of the implicit grant type
	- Check **Flawed CSRF** protection
		- Check if no **state** parameter or any other anti CSRF token used
	- Check for **leaking authorization codes and access tokens**
		- Check **redirect_uri** parameter & **callback** endpoint
			- **state** and **nonce** does not fully prevent attacks
			- Attacker can **generate new vaules** from browser
	- Check for **flawed redirect_uri** validation
		- Remove or add arbitary paths, query parameters and fragments
		- Try using bypasses from [CSRF](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses), [CORS](https://portswigger.net/web-security/cors#errors-parsing-origin-headers) e.g `https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/`
		- Check for parameter pollution
			- Try duplicate parameters
				- `..client-app.com/callback&redirect_uri=evil-user.net``
		- Check if `localhost` URIs bypass filters
		- Try changing other parameters e.g `web_message`
	- Check if stealing codes and access tokens via a **proxy page** possible
		- Check if LFI possible `https://client-app.com/oauth/callback/../../example/path
		- Check open redirects
- Check **authorization code flow**
	- Check if you can register you own applicaiton
		- Check if scope can be changed
- Check for **scope upgrade implicit flow**
	- Check when token found if scope can be changed when querying API `/userinfo`
- Check **unverified user registration**
	- Check if you can register an account using the same details as a target user 
* Check OpenID unprotected dynamic client registration
	* Check if you can register a application
* Check OpenID allowing authorization requests by reference
	* Check if option is enabled ``request_uri_parameter_supported``