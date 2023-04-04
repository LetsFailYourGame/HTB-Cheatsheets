![](jwt-infographic.jpg)

## What are JWTs?
* Standardized format for sending cryptographically signed JSON data between systems
* Can theoretically contain any kind of data
* Most commonly used to send information ("claims") about users as part of authentication, session handling, and access control mechanisms
* Unlike with classic session tokens, all of the data that a server needs is stored client-side within the JWT itself

### JWT format
* Consists of 3 parts: a header, a payload, and a signature
* Seperated by "."
* Header and payload parts of a JWT base64url-encoded JSON objects
* Header contains metadata about the token itself
* Payload contains the actual "claims" about the user

```jwt
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5kT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA
```

```json
{ 
	"iss": "portswigger", 
	"exp": 1648037164, 
	"name": "Carlos Montoya", 
	"sub": "carlos", 
	"role": "blog_author", 
	"email": "carlos@carlos-montoya.net", 
	"iat": 1516239022 
}
```

* This data can be easily read or modified by anyone with access to the token
* Therefore, the security of any JWT-based mechanism is heavily reliant on the cryptographic signature

### JWT signature
* The server that issues the token typically generates the signature by hashing the header and payload
* In some cases, they also encrypt the resulting hash
* Either way, this process involves a secret signing key
* This mechanism provides a way for servers to verify that none of the data within the token has been tampered with since it was issued
* As the signature is directly derived from the rest of the token, changing a single byte of the header or payload results in a mismatched signature
- Without knowing the server's secret signing key, it shouldn't be possible to generate the correct signature for a given header or payload

### JWT vs JWS vs JWE
* JWT specification is actually very limited
* Only defines a format for representing information ("claims") as a JSON object that can be transferred between two parties
* JWTs aren't really used as a standalone entity
* The JWT spec is extended by both the JSON Web Signature (JWS) and JSON Web Encryption (JWE) specifications, which define concrete ways of actually implementing JWTs

![](jwt-jws-jwe.jpg)

* JWT is usually either a JWS or JWE token
* When people use the term "JWT", they almost always mean a JWS token
* JWEs are very similar, except that the actual contents of the token are encrypted rather than just encoded

## What are JWT attacks?
* JWT attacks involve a user sending modified JWTs to the server in order to achieve a malicious goal
* Typically, this goal is to bypass authentication and [access controls](https://portswigger.net/web-security/access-control) by impersonating another user who has already been authenticated

## What is the impact of JWT attacks?
If an attacker is able to create their own valid tokens with arbitrary values, they may be able to escalate their own privileges or impersonate other users, taking full control of their accounts

## How do vulnerabilities to JWT attacks arise?
* Vulnerabilities typically arise due to flawed JWT handling within the application itself
* Implementation flaws usually mean that the signature of the JWT is not verified properly
* This enables an attacker to tamper with the values passed to the application via the token's payload
* Even if the signature is robustly verified, whether it can truly be trusted relies heavily on the server's secret key remaining a secret
* If this key is leaked in some way, or can be guessed or brute-forced, an attacker can generate a valid signature for any arbitrary token, compromising the entire mechanism

## Exploiting flawed JWT signature verification
* Servers don't usually store any information about the JWTs that they issue
* Each token is an entirely self-contained entity
* The server doesn't actually know anything about the original contents of the token, or even what the original signature was
* If the server doesn't verify the signature properly, there's nothing to stop an attacker from making arbitrary changes to the rest of the token

```json
{ "username": "carlos", "isAdmin": false }
```

If the server identifies the session based on this `username`, modifying its value might enable an attacker to impersonate other logged-in users. Similarly, if the `isAdmin` value is used for access control, this could provide a simple vector for privilege escalation.

### Accepting arbitrary signatures
* JWT libraries typically provide one method for **verifying tokens** and another that **just decodes them**
* For example, the Node.js library `jsonwebtoken` has `verify()` and `decode()`
* Occasionally, developers confuse these two methods and only pass incoming tokens to the `decode()` method
* This effectively means that the application doesn't verify the signature at all

### Accepting tokens with no signature
* JWT header contains an `alg` parameter
* This tells the server which algorithm was used to sign the token and, therefore, which algorithm it needs to use when verifying the signature

```json
{ "alg": "HS256", "typ": "JWT" }
```

* This is inherently flawed because the server has no option but to implicitly trust user-controllable input from the token which, at this point, hasn't been verified at all
* In other words, an attacker can directly influence how the server checks whether the token is trustworthy
* JWTs can be signed using a range of different algorithms, but can also be left unsigned
* In this case, the `alg` parameter is set to `none`, which indicates a so-called **"unsecured JWT"**
* Due to the obvious dangers of this, servers usually reject tokens with no signature
* However, as this kind of filtering relies on string parsing, you can sometimes bypass these filters using classic obfuscation techniques, such as mixed capitalization and unexpected encodings

Even if the token is unsigned, the payload part must still be terminated with a trailing dot.

## Brute-forcing secret keys
* Some signing algorithms, such as HS256 (HMAC + SHA-256), use an arbitrary, standalone string as the secret key
* Just like a password, it's crucial that this secret can't be easily guessed or brute-forced by an attacker
* Developers sometimes make mistakes like forgetting to change default or placeholder secrets
* They may even copy and paste code snippets they find online, then forget to change a hardcoded secret that's provided as an example

```sh
hashcat -a 0 -m 16500 <jwt> <wordlist>

# Format generated
<jwt>:<identified-secret>
```

## JWT header parameter injections
* Only the `alg` header parameter is mandatory
* In practice, however, JWT headers (also known as JOSE headers) often contain several other parameters
* Interesting for us
	- `jwk` (JSON Web Key)
		- Provides an embedded JSON object representing the key
	- `jku` (JSON Web Key Set URL) 
		- Provides a URL from which servers can fetch a set of keys containing the correct key
	- `kid` (Key ID) 
		- Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching `kid` parameter
- These user-controllable parameters each tell the recipient server which key to use when verifying the signature

### Injecting self-signed JWTs via the jwk parameter
The JSON Web Signature (JWS) specification describes an optional `jwk` header parameter, which servers can use to embed their public key directly within the token itself in JWK format. `A JWK (JSON Web Key) is a standardized format for representing keys as a JSON object.` 

```json
{ 
	"kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG", 
	"typ": "JWT", 
	"alg": "RS256", 
	"jwk": 
	{ 
		"kty": "RSA", 
		"e": "AQAB", 
		"kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG", 
		"n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m" 
	} 
}
```

* Ideally, servers should only use a limited whitelist of public keys to verify JWT signatures
* **Misconfigured servers** sometimes use any key that's embedded in the `jwk` parameter
* Exploit this behavior by signing a modified JWT using your own RSA private key, then embedding the matching public key in the `jwk` header

### Injecting self-signed JWTs via the jku parameter
* Instead of embedding public keys directly using the `jwk` header parameter, some servers let you use the `jku` (JWK Set URL) header parameter to reference a JWK Set containing the key
* When verifying the signature, the server fetches the relevant key from this URL
* `A JWK Set is a JSON object containing an array of JWKs representing different keys`

```json
{ 
	"keys": [ 
		{ 
		"kty": "RSA", 
		"e": "AQAB", 
		"kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab", 
		"n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
		}, 
		{ 
		"kty": "RSA",
		"e": "AQAB", 
		"kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA", 
		"n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw" 
		} 
	] 
}
```

* JWK Sets like this are sometimes exposed publicly via a standard endpoint, such as `/.well-known/jwks.json`

### Injecting self-signed JWTs via the kid parameter
* Servers may use several cryptographic keys for signing different kinds of data, not just JWTs
* For this reason, the header of a JWT may contain a `kid` (Key ID) parameter, which helps the server identify which key to use when verifying the signature
* Verification keys are often stored as a JWK Set
* In this case, the server may simply look for the JWK with the same `kid` as the token
* However, the JWS specification doesn't define a concrete structure for this ID - it's just an arbitrary string of the developer's choosing
* For example, they might use the `kid` parameter to point to a particular entry in a database, or even the name of a file
* If this parameter is also vulnerable to [directory traversal](https://portswigger.net/web-security/file-path-traversal), an attacker could potentially force the server to use an arbitrary file from its filesystem as the verification key

```json
{ 
	"kid": "../../path/to/file", 
	"typ": "JWT", 
	"alg": "HS256", 
	"k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc" 
}
```

* This is especially dangerous if the server also supports JWTs signed using a symmetric algorithm
* In this case, an attacker could potentially point the `kid` parameter to a predictable, static file, then sign the JWT using a secret that matches the contents of this file
* You could theoretically do this with any file, but one of the simplest methods is to use `/dev/null`
* Signs token with empty string

If you're using the JWT Editor extension, note that this doesn't let you sign tokens using an empty string. However, due to a bug in the extension, you can get around this by using a Base64-encoded null byte.

### Other interesting JWT header parameters
- `cty` (Content Type) - Sometimes used to declare a media type for the content in the JWT payload. This is usually omitted from the header, but the underlying parsing library may support it anyway. If you have found a way to bypass signature verification, you can try injecting a `cty` header to change the content type to `text/xml` or `application/x-java-serialized-object`, which can potentially enable new vectors for [XXE](https://portswigger.net/web-security/xxe) and [deserialization](https://portswigger.net/web-security/deserialization) attacks.
- `x5c` (X.509 Certificate Chain) - Sometimes used to pass the X.509 public key certificate or certificate chain of the key used to digitally sign the JWT. This header parameter can be used to inject self-signed certificates, similar to the [`jwk` header injection](https://portswigger.net/web-security/jwt#injecting-self-signed-jwts-via-the-jwk-parameter) attacks discussed above. Due to the complexity of the X.509 format and its extensions, parsing these certificates can also introduce vulnerabilities. Details of these attacks are beyond the scope of these materials, but for more details, check out [CVE-2017-2800](https://talosintelligence.com/vulnerability_reports/TALOS-2017-0293) and [CVE-2018-2633](https://mbechler.github.io/2018/01/20/Java-CVE-2018-2633).

## JWT algorithm confusion
* Occur when an attacker is able to force the server to verify the signature of a JSON web token ([JWT](https://portswigger.net/web-security/jwt)) using a different algorithm than is intended by the website's developers

#### Symmetric vs asymmetric algorithms

![](jwt-symmetric-signing-algorithm.jpg)

![](jwt-asymmetric-signing-algorithm.jpg)

#### How do algorithm confusion vulnerabilities arise?
* Arise due to flawed implementation of JWT libraries
* Many libraries provide a single, algorithm-agnostic method for verifying signatures
* These methods rely on the `alg` parameter in the token's header to determine the type of verification they should perform
* Simplified pseudo code example

```js
function verify(token, secretOrPublicKey)
{ 
	algorithm = token.getAlgHeader(); 
	if(algorithm == "RS256")
		{ // Use the provided key as an RSA public key } 
	else if (algorithm == "HS256")
		{ // Use the provided key as an HMAC secret key } 
	}
```

* Problems arise when website developers who subsequently use this method assume that it will exclusively handle JWTs signed using an asymmetric algorithm like RS256
* Due to this flawed assumption, they may always pass a fixed public key to the method as follows

```js
publicKey = <public-key-of-server>; 
token = request.getCookie("session"); 
verify(token, publicKey);
```

* In this case, if the server receives a token signed using a symmetric algorithm like HS256, the library's generic `verify()` method will treat the public key as an HMAC secret
* This means that an attacker could sign the token using HS256 and the public key, and the server will use the same public key to verify the signature

The public key you use to sign the token must be absolutely identical to the public key stored on the server. This includes using the same format (such as X.509 PEM) and preserving any non-printing characters like newlines. In practice, you may need to experiment with different formatting in order for this attack to work.

#### Performing an algorithm confusion attack
1.  [Obtain the server's public key](https://portswigger.net/web-security/jwt/algorithm-confusion#step-1-obtain-the-server-s-public-key)
2.  [Convert the public key to a suitable format](https://portswigger.net/web-security/jwt/algorithm-confusion#step-2-convert-the-public-key-to-a-suitable-format)
3.  [Create a malicious JWT](https://portswigger.net/web-security/jwt/algorithm-confusion#step-3-modify-your-jwt) with a modified payload and the `alg` header set to `HS256`.
4.  [Sign the token with HS256](https://portswigger.net/web-security/jwt/algorithm-confusion#step-4-sign-the-jwt-using-the-public-key), using the public key as the secret.

## How to prevent JWT attacks
You can protect your own websites against many of the attacks we've covered by taking the following high-level measures:
-   Use an up-to-date library for handling JWTs and make sure your developers fully understand how it works, along with any security implications. Modern libraries make it more difficult for you to inadvertently implement them insecurely, but this isn't foolproof due to the inherent flexibility of the related specifications.  
-   Make sure that you perform robust signature verification on any JWTs that you receive, and account for edge-cases such as JWTs signed using unexpected algorithms.
-   Enforce a strict whitelist of permitted hosts for the `jku` header.
-   Make sure that you're not vulnerable to [path traversal](https://portswigger.net/web-security/file-path-traversal) or SQL injection via the `kid` header parameter.

### Additional best practice for JWT handling
Although not strictly necessary to avoid introducing vulnerabilities, we recommend adhering to the following best practice when using JWTs in your applications:
-   Always set an expiration date for any tokens that you issue.
-   Avoid sending tokens in URL parameters where possible.
-   Include the `aud` (audience) claim (or similar) to specify the intended recipient of the token. This prevents it from being used on different websites.
-   Enable the issuing server to revoke tokens (on logout, for example).

## Refs
* Working with JWT in [Burp](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts)
* [JWT](https://portswigger.net/web-security/jwt)
* [AlgConfusion](https://portswigger.net/web-security/jwt/algorithm-confusion)