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
* Check for deriving public keys from existing tokens 
	* `docker run --rm -it portswigger/sig2n <token1> <token2>`