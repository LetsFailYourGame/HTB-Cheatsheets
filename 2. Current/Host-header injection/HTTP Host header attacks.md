![](host-header-attacks.jpg)

## What is the HTTP Host header?
* The HTTP Host header is a mandatory request header as of HTTP/1.1
* Specifies the domain name that the client wants to access
* In some cases, such as when the request has been forwarded by an intermediary system, the Host value may be altered before it reaches the intended back-end component

```HTTP
GET /web-security HTTP/1.1 
Host: portswigger.net
```

## What is the purpose of the HTTP Host header?
* Purpose of the HTTP Host header is to help identify which back-end component the client wants to communicate with
* If requests didn't contain Host headers, or if the Host header was malformed in some way, this could lead to issues when routing incoming requests to the intended application
* Historically, this ambiguity didn't exist because each IP address would only host content for a single domain
* Nowadays, largely due to the ever-growing trend for cloud-based solutions and outsourcing much of the related architecture, it is common for multiple websites and applications to be accessible at the same IP address
* When multiple applications are accessible via the same IP address, this is most commonly a result of one of the following scenarios

### Virtual hosting
* This could be multiple websites with a single owner, but it is also possible for websites with different owners to be hosted on a single, shared platform
* This is less common than it used to be, but still occurs with some cloud-based SaaS solutions
* In either case, although each of these distinct websites will have a different domain name, they all share a common IP address with the server
* Websites hosted in this way on a single server are known as "virtual hosts"
* To a normal user accessing the website, a virtual host is often indistinguishable from a website being hosted on its own dedicated server

### Routing traffic via an intermediary
* When websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system
* This could be a simple load balancer or a reverse proxy server of some kind
* This setup is especially used in cases where clients access the website via a content delivery network (CDN)
* In this case, even though the websites are hosted on separate back-end servers, all of their domain names resolve to a single IP address of the intermediary component
* This presents some of the same challenges as virtual hosting because the reverse proxy or load balancer needs to know the appropriate back-end to which it should route each request

### How does the HTTP Host header solve this problem?
* In both of these scenarios, the Host header is relied on to specify the intended recipient
* When a browser sends the request, the target URL will resolve to the IP address of a particular server
* When this server receives the request, it refers to the Host header to determine the intended back-end and forwards the request accordingly

## What is an HTTP Host header attack?
* Attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way
* If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior
* Attacks that involve injecting a payload directly into the Host header are often known as "Host header injection" attacks
* Off-the-shelf web applications typically don't know what domain they are deployed on unless it is manually specified in a configuration file during setup
* When they need to know the current domain, for example, to generate an absolute URL included in an email, they may resort to retrieving the domain from the Host header

```HTML
<a href="https://_SERVER['HOST']/support">Contact support</a>
```

* The header value may also be used in a variety of interactions between different systems of the website's infrastructure
* As the Host header is in fact user controllable, this practice can lead to a number of issues
* If the input is not properly escaped or validated, the Host header is a potential vector for exploiting a range of other vulnerabilities, most notably
	- Web cache poisoning
	- Business [logic flaws](https://portswigger.net/web-security/logic-flaws) in specific functionality
	- Routing-based SSRF
	- Classic server-side vulnerabilities, such as SQL injection

## How do HTTP Host header vulnerabilities arise?
* Due to the flawed assumption that the header is not user controllable
* Creates implicit trust in the Host header and results in inadequate validation or escaping of its value, even though an attacker can easily modify this using tools like Burp Proxy
* Even if the Host header itself is handled more securely, depending on the configuration of the servers that deal with incoming requests, the Host can potentially be overridden by injecting other headers
* Sometimes website owners are unaware that these headers are supported by default and, as a result, they may not be treated with the same level of secrurity
* Many of these vulnerabilities arise not because of insecure coding but because of insecure configuration of one or more components in the related infrastructure
* These configuration issues can occur because websites integrate third-party technologies into their architecture without necessarily understanding the configuration options and their security implications

## How to prevent HTTP Host header attacks
To prevent HTTP Host header attacks, the simplest approach is to avoid using the Host header altogether in server-side code. Double-check whether each URL really needs to be absolute. You will often find that you can just use a relative URL instead. This simple change can help you prevent [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) vulnerabilities in particular.

Other ways to prevent HTTP Host header attacks include:

##### Protect absolute URLs
When you have to use absolute URLs, you should require the current domain to be manually specified in a configuration file and refer to this value instead of the Host header. This approach would eliminate the threat of password reset poisoning, for example.

##### Validate the Host header
If you must use the Host header, make sure you validate it properly. This should involve checking it against a whitelist of permitted domains and rejecting or redirecting any requests for unrecognized hosts. You should consult the documentation of your framework for guidance on how to do this. For example, the Django framework provides the `ALLOWED_HOSTS` option in the settings file. This approach will reduce your exposure to Host header injection attacks.

##### Don't support Host override headers
It is also important to check that you do not support additional headers that may be used to construct these attacks, in particular `X-Forwarded-Host`. Remember that these may be supported by default.

##### Whitelist permitted domains
To prevent routing-based attacks on internal infrastructure, you should configure your load balancer or any reverse proxies to forward requests only to a whitelist of permitted domains.

##### Be careful with internal-only virtual hosts
When using virtual hosting, you should avoid hosting internal-only websites and applications on the same server as public-facing content. Otherwise, attackers may be able to access internal domains via Host header manipulation.

## How to test for vulnerabilities using the HTTP Host header
* You need to identify whether you are able to modify the Host header and still reach the target application with your request
* If so, you can use this header to probe the application and observe what effect this has on the response

### Supply an arbitrary Host header
* The first step is to test what happens when you supply an arbitrary, unrecognized domain name via the Host header
* Some intercepting proxies derive the target IP address from the Host header directly, which makes this kind of testing all but impossible; any changes you made to the header would just cause the request to be sent to a completely different IP address
* However, Burp Suite accurately maintains the separation between the Host header and the target IP address
* This separation allows you to supply any arbitrary or malformed Host header that you want, while still making sure that the request is sent to the intended target
* Sometimes, you will still be able to access the target website even when you supply an unexpected Host header
* Maybe server is configured with a default option or fallback in case they receive requests for domain names that they don't recognize
* On the other hand, as the Host header is such a fundamental part of how the websites work, tampering with it often means you will be unable to reach the target application at all
* The front-end server or load balancer that received your request may simply not know where to forward it, resulting in an "`Invalid Host header`" error of some kind
* This is especially likely if your target is accessed via a CDN
* In this case, you should move on to trying some of the other techniques

### Check for flawed validation
* Instead of receiving an "`Invalid Host header`" response, you might find that your request is blocked as a result of some kind of security measure
* For example, some websites will validate whether the Host header matches the SNI from the TLS handshake
* This doesn't necessarily mean that they're immune to Host header attacks
* You should try to understand how the website parses the Host header
* This can sometimes reveal loopholes that can be used to bypass the validation
* For example, some parsing algorithms will omit the port from the Host header, meaning that only the domain name is validated
* If you are also able to supply a non-numeric port, you can leave the domain name untouched to ensure that you reach the target application, while potentially injecting a payload via the port

```http
GET /example HTTP/1.1 
Host: vulnerable-website.com:bad-stuff-here
```

* Other sites will try to apply matching logic to allow for arbitrary subdomains
* In this case, you may be able to bypass the validation entirely by registering an arbitrary domain name that ends with the same sequence of characters as a whitelisted one

```http
GET /example HTTP/1.1 
Host: notvulnerable-website.com
```

* Alternatively, you could take advantage of a less-secure subdomain that you have already compromised

```http
GET /example HTTP/1.1 
Host: hacked-subdomain.vulnerable-website.com
```

### Send ambiguous requests
* The code that validates the host and the code that does something vulnerable with it often reside in different application components or even on separate servers
* By identifying and exploiting discrepancies in how they retrieve the Host header, you may be able to issue an ambiguous request that appears to have a different host depending on which system is looking at it

#### Inject duplicate Host headers
* Try adding duplicate Host headers
* Admittedly, this will often just result in your request being blocked
* However, as a browser is unlikely to ever send such a request, you may occasionally find that developers have not anticipated this scenario
* Different systems and technologies will handle this case differently, but it is common for one of the two headers to be given precedence over the other one, effectively overriding its value
* When systems disagree about which header is the correct one, this can lead to discrepancies that you may be able to exploit

```http
GET /example HTTP/1.1 
Host: vulnerable-website.com 
Host: bad-stuff-here
```

Let's say the front-end gives precedence to the first instance of the header, but the back-end prefers the final instance. Given this scenario, you could use the first header to ensure that your request is routed to the intended target and use the second header to pass your payload into the server-side code.

#### Supply an absolute URL
* Although the request line typically specifies a relative path on the requested domain, many servers are also configured to understand requests for absolute URLs
* The ambiguity caused by supplying both an absolute URL and a Host header can also lead to discrepancies between different systems
* Officially, the request line should be given precedence when routing the request but, in practice, this isn't always the case
* Servers will sometimes behave differently depending on whether the request line contains an HTTP or an HTTPS URL

```http
GET https://vulnerable-website.com/ HTTP/1.1 
Host: bad-stuff-here
```

#### Add line wrapping
* You can also uncover quirky behavior by indenting HTTP headers with a space character
* Some servers will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header's value
* Other servers will ignore the indented header altogether
* Due to the highly inconsistent handling of this case, there will often be discrepancies between different systems that process your request
* The website may block requests with multiple Host headers, but you may be able to bypass this validation by indenting one of them

```http
GET /example HTTP/1.1 
	Host: bad-stuff-here 
Host: vulnerable-website.com
```

* If the front-end ignores the indented header, the request will be processed as an ordinary request for `vulnerable-website.com`
* Now let's say the back-end ignores the leading space and gives precedence to the first header in the case of duplicates
* This discrepancy might allow you to pass arbitrary values via the "wrapped" Host header

### Inject host override headers
* Even if you can't override the Host header using an ambiguous request, there are other possibilities for overriding its value while leaving it intact
* This includes injecting your payload via one of several other HTTP headers that are designed to serve just this purpose, albeit for more innocent use cases
* As we've already discussed, websites are often accessed via some kind of intermediary system, such as a load balancer or a reverse proxy
* In this kind of architecture, the Host header that the back-end server receives may contain the domain name for one of these intermediary systems
* This is usually not relevant for the requested functionality
* To solve this problem, the front-end may inject the `X-Forwarded-Host` header, containing the original value of the Host header from the client's initial request
* For this reason, when an `X-Forwarded-Host` header is present, many frameworks will refer to this instead
* You may observe this behavior even when there is no front-end that uses this header
* You can sometimes use `X-Forwarded-Host` to inject your malicious input while circumventing any validation on the Host header itself

```http
GET /example HTTP/1.1 
Host: vulnerable-website.com 
X-Forwarded-Host: bad-stuff-here
```

* From a security perspective, it is important to note that some websites, potentially even your own, support this kind of behavior unintentionally
* This is usually because one or more of these headers is enabled by default in some third-party technology that they use

## How to exploit the HTTP Host header
* Once you have identified that you can pass arbitrary hostnames to the target application, you can start to look for ways to exploit it

### Password reset poisoning
![](2.%20Current/Host-header%20injection/Screenshots/password-reset-poisoning.svg)
### Web cache poisoning via the Host header
* When probing for potential Host header attacks, you will often come across seemingly vulnerable behavior that isn't directly exploitable
* For example, you may find that the Host header is reflected in the response markup without HTML-encoding, or even used directly in script imports
* Reflected, client-side vulnerabilities, such as [XSS](https://portswigger.net/web-security/cross-site-scripting), are typically not exploitable when they're caused by the Host header
* There is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner
* However, if the target uses a web cache, it may be possible to turn this useless, reflected vulnerability into a dangerous, stored one by persuading the cache to serve a poisoned response to other users
* To construct a web cache poisoning attack, you need to elicit a response from the server that reflects an injected payload
* The challenge is to do this while preserving a cache key that will still be mapped to other users' requests
* If successful, the next step is to get this malicious response cached
* It will then be served to any users who attempt to visit the affected page
* Standalone caches typically include the Host header in the cache key, so this approach usually works best on integrated, application-level caches

### Exploiting classic server-side vulnerabilities
Every HTTP header is a potential vector for exploiting classic server-side vulnerabilities, and the Host header is no exception. For example, you should try the usual [SQL injection](https://portswigger.net/web-security/sql-injection) probing techniques via the Host header. If the value of the header is passed into a SQL statement, this could be exploitable.

### Accessing restricted functionality
For fairly obvious reasons, it is common for websites to restrict access to certain functionality to internal users only. However, some websites' [access control](https://portswigger.net/web-security/access-control) features make flawed assumptions that allow you to bypass these restrictions by making simple modifications to the Host header. This can expose an increased attack surface for other exploits.

### Accessing internal websites with virtual host brute-forcing
Companies sometimes make the mistake of hosting publicly accessible websites and private, internal sites on the same server. Servers typically have both a public and a private IP address. As the internal hostname may resolve to the private IP address, this scenario can't always be detected simply by looking at DNS records:

```dns
www.example.com: 12.34.56.78 
intranet.example.com: 10.0.0.132
```

In some cases, the internal site might not even have a public DNS record associated with it. Nonetheless, an attacker can typically access any virtual host on any server that they have access to, provided they can guess the hostnames. If they have discovered a hidden domain name through other means, such as [information disclosure](https://portswigger.net/web-security/information-disclosure), they could simply request this directly. Otherwise, they can use tools like Burp Intruder to brute-force virtual hosts using a simple wordlist of candidate subdomains.

### Routing-based SSRF


## Interesting
* [SSRF](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface) with host header