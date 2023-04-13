* Accepting arbitrary signatures (**code audit**)
	* Check for only `decode()` use e.g `verify()` is missing
	* Check for hardcoded secrets / default credentials / copied code
* Accepting tokens with no signature
	* Check if `alg: none` is accepted
	* Check for bypass when not accepted
		* Mixed capital letters
		* Unexpected encoding
* Check for unsecure secret keys used (`alg: HS256`)
	* Dictionary attack
* Check interesting parameters
	* `jwk`
		* Check if signing with own public key is working
	* `jku`
		* Check exposed standart endpoint 
			* `/.well-known/jwks.json`
			* `/jwks.json`
		* Server webserver with own JWK
			* Add `jku` with the url
			* Change JWK payload
			* Self sign it with the key
			* Check if accepted
	* `kid`
		* Check if `kid` is vulnerable to LFI
		* Chose any other file in the filesystem as the key
			* For example from an upload directory
		* Check for symetric key algorithm
			* Use contents of a static file as key for signing
			* `/dev/null` signs the token with an empty string
	* `cty`
	* `x5c`
* Check for key algorithm confusion
	1.  [Obtain the server's public key](https://portswigger.net/web-security/jwt/algorithm-confusion#step-1-obtain-the-server-s-public-key)
	2.  [Convert the public key to a suitable format](https://portswigger.net/web-security/jwt/algorithm-confusion#step-2-convert-the-public-key-to-a-suitable-format)
	3.  [Create a malicious JWT](https://portswigger.net/web-security/jwt/algorithm-confusion#step-3-modify-your-jwt) with a modified payload and the `alg` header set to `HS256`.
	4.  [Sign the token with HS256](https://portswigger.net/web-security/jwt/algorithm-confusion#step-4-sign-the-jwt-using-the-public-key), using the public key as the secret.
* Check for deriving public keys from existing tokens 
	* `docker run --rm -it portswigger/sig2n <token1> <token2>`