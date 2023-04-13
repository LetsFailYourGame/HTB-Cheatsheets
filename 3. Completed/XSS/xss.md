![](cross-site-scripting.svg)
## What is cross-site scripting (XSS)?
* It allows an attacker to circumvent the same origin policy, which is designed to segregate different websites from each other
* Cross-site scripting vulnerabilities normally allow an attacker to masquerade as a victim user, to carry out any actions that the user is able to perform, and to access any of the user's data
* If the victim user has privileged access within the application, then the attacker might be able to gain full control over all of the application's functionality and data

## How does XSS work?
* Cross-site scripting works by manipulating a vulnerable web site so that it returns malicious JavaScript to users
* When the malicious code executes inside a victim's browser, the attacker can fully compromise their interaction with the application

## XSS proof of concept
* It's long been common practice to use the `alert()` function for this purpose because it's short, harmless, and pretty hard to miss when it's successfully called
* Unfortunately, there's a slight hitch if you use Chrome
* **From version 92 onward (July 20th, 2021), cross-origin iframes are prevented from calling `alert()`**
* As these are used to construct some of the more advanced XSS attacks, you'll sometimes need to use an alternative PoC payload
* In this scenario, we recommend the `print()` function
* If you're interested in learning more about this change and why we like `print()`, [check out our blog post](https://portswigger.net/research/alert-is-dead-long-live-print) on the subject

## What are the types of XSS attacks?
- [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting#reflected-cross-site-scripting), where the malicious script comes from the current HTTP request
- [Stored XSS](https://portswigger.net/web-security/cross-site-scripting#stored-cross-site-scripting), where the malicious script comes from the website's database
- [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting#dom-based-cross-site-scripting), where the vulnerability exists in client-side code rather than server-side code

## [Reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected)
* Simplest variety of cross-site scripting
* Arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way

```python
https://insecure-website.com/status?message=All+is+well. 

<p>Status: All is well.</p>
```

```python
https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script> 

<p>Status: <script>/* Bad stuff here... */</script></p>
```

## Impact
* `Medium+`

## How to find and test for reflected XSS vulnerabilities
- **Test every entry point.** Test separately every entry point for data within the application's HTTP requests. This includes parameters or other data within the URL query string and message body, and the URL file path. It also includes HTTP headers, although XSS-like behavior that can only be triggered via certain HTTP headers may not be exploitable in practice.
- **Submit random alphanumeric values.** For each entry point, submit a unique random value and determine whether the value is reflected in the response. The value should be designed to survive most input validation, so needs to be fairly short and contain only alphanumeric characters. But it needs to be long enough to make accidental matches within the response highly unlikely. A random alphanumeric value of around 8 characters is normally ideal. You can use Burp Intruder's number [payloads](https://portswigger.net/burp/documentation/desktop/tools/intruder/payloads/types#numbers) with randomly generated hex values to generate suitable random values. And you can use Burp Intruder's [grep payloads settings](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/settings#grep-payloads) to automatically flag responses that contain the submitted value.
- **Determine the reflection context.** For each location within the response where the random value is reflected, determine its context. This might be in text between HTML tags, within a tag attribute which might be quoted, within a JavaScript string, etc.
- **Test a candidate payload.** Based on the context of the reflection, test an initial candidate XSS payload that will trigger JavaScript execution if it is reflected unmodified within the response. The easiest way to test payloads is to send the request to [Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater), modify the request to insert the candidate payload, issue the request, and then review the response to see if the payload worked. An efficient way to work is to leave the original random value in the request and place the candidate XSS payload before or after it. Then set the random value as the search term in Burp Repeater's response view. Burp will highlight each location where the search term appears, letting you quickly locate the reflection.
- **Test alternative payloads.** If the candidate XSS payload was modified by the application, or blocked altogether, then you will need to test alternative payloads and techniques that might deliver a working XSS attack based on the context of the reflection and the type of input validation that is being performed. For more details, see [cross-site scripting contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- **Test the attack in a browser.** Finally, if you succeed in finding a payload that appears to work within Burp Repeater, transfer the attack to a real browser (by pasting the URL into the address bar, or by modifying the request in [Burp Proxy's intercept view](https://portswigger.net/burp/documentation/desktop/tools/proxy/intercept-messages), and see if the injected JavaScript is indeed executed. Often, it is best to execute some simple JavaScript like `alert(document.domain)` which will trigger a visible popup within the browser if the attack succeeds.

## Common questions about reflected cross-site scripting
**What is the difference between reflected XSS and** [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)**?** Reflected XSS arises when an application takes some input from an HTTP request and embeds that input into the immediate response in an unsafe way. With stored XSS, the application instead stores the input and embeds it into a later response in an unsafe way.

**What is the difference between reflected XSS and self-XSS?** Self-XSS involves similar application behavior to regular reflected XSS, however it cannot be triggered in normal ways via a crafted URL or a cross-domain request. Instead, the vulnerability is only triggered if the victim themselves submits the XSS payload from their browser. Delivering a self-XSS attack normally involves socially engineering the victim to paste some attacker-supplied input into their browser. As such, it is normally considered to be a lame, low-impact issue.

## [Stored cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/stored)
* Also known as persistent or second-order XSS
* Arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way
* The data in question might be submitted to the application via HTTP requests; for example, comments on a blog post, user nicknames in a chat room, or contact details on a customer order
* In other cases, the data might arrive from other untrusted sources; for example, a webmail application displaying messages received over SMTP, a marketing application displaying social media posts, or a network monitoring application displaying packet data from network traffic

```http
POST /post/comment HTTP/1.1 
Host: vulnerable-website.com 
Content-Length: 100 

postId=3&comment=This+post+was+extremely+helpful.&name=Carlos+Montoya&email=carlos%40normal-user.net
```

```python
<p>This post was extremely helpful.</p>
```

* Assuming the application doesn't perform any other processing of the data, an attacker can submit a malicious comment

```python 
<script>/* Bad stuff here... */</script>
```

```python
comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E
```

```python
<p><script>/* Bad stuff here... */</script></p>
```

## Impact
* `Medium - High`

## How to find and test for stored XSS vulnerabilities
Testing for stored XSS vulnerabilities manually can be challenging. You need to test all relevant "entry points" via which attacker-controllable data can enter the application's processing, and all "exit points" at which that data might appear in the application's responses.

Entry points into the application's processing include:
- Parameters or other data within the URL query string and message body
- The URL file path
- HTTP request headers that might not be exploitable in relation to [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- Any out-of-band routes via which an attacker can deliver data into the application. The routes that exist depend entirely on the functionality implemented by the application: a webmail application will process data received in emails; an application displaying a Twitter feed might process data contained in third-party tweets; and a news aggregator will include data originating on other web sites.

The exit points for stored XSS attacks are all possible HTTP responses that are returned to any kind of application user in any situation.

The first step in testing for stored XSS vulnerabilities is to locate the links between entry and exit points, whereby data submitted to an entry point is emitted from an exit point. The reasons why this can be challenging are that:
- Data submitted to any entry point could in principle be emitted from any exit point. For example, user-supplied display names could appear within an obscure audit log that is only visible to some application users.
- Data that is currently stored by the application is often vulnerable to being overwritten due to other actions performed within the application. For example, a search function might display a list of recent searches, which are quickly replaced as users perform other searches.

A more realistic approach is to work systematically through the data entry points, submitting a specific value into each one, and monitoring the application's responses to detect cases where the submitted value appears. Particular attention can be paid to relevant application functions, such as comments on blog posts. When the submitted value is observed in a response, you need to determine whether the data is indeed being stored across different requests, as opposed to being simply reflected in the immediate response.

When you have identified links between entry and exit points in the application's processing, each link needs to be specifically tested to detect if a stored XSS vulnerability is present. This involves determining the context within the response where the stored data appears and testing suitable candidate XSS payloads that are applicable to that context. At this point, the testing methodology is broadly the same as for finding [reflected XSS vulnerabilities](https://portswigger.net/web-security/cross-site-scripting/reflected).

## DOM-based cross-site scripting
* Arises when an application contains some client-side JavaScript that processes data from an untrusted source in an unsafe way, usually by writing the data back to the DOM
* In the following example, an application uses some JavaScript to read the value from an input field and write that value to an element within the HTML

```python
var search = document.getElementById('search').value; 
var results = document.getElementById('results'); 
results.innerHTML = 'You searched for: ' + search;
```

* If the attacker can control the value of the input field, they can easily construct a malicious value that causes their own script to execute

```python
You searched for: <img src=1 onerror='/* Bad stuff here... */'>
```

* The most common source for DOM XSS is the URL, which is typically accessed with the `window.location` object
* An attacker can construct a link to send a victim to a vulnerable page with a payload in the query string and fragment portions of the URL
* In certain circumstances, such as when targeting a 404 page or a website running PHP, the payload can also be placed in the path

## How to test for DOM-based cross-site scripting
To test for DOM-based cross-site scripting manually, you generally need to use a browser with developer tools, such as Chrome. You need to work through each available source in turn, and test each one individually.

### Testing HTML sinks
To test for DOM XSS in an HTML sink, place a random alphanumeric string into the source (such as `location.search`), then use developer tools to inspect the HTML and find where your string appears. Note that the browser's "View source" option won't work for DOM XSS testing because it doesn't take account of changes that have been performed in the HTML by JavaScript. In Chrome's developer tools, you can use `Control+F` (or `Command+F` on MacOS) to search the DOM for your string.

For each location where your string appears within the DOM, you need to identify the context. Based on this context, you need to refine your input to see how it is processed. For example, if your string appears within a double-quoted attribute then try to inject double quotes in your string to see if you can break out of the attribute.

Note that browsers behave differently with regards to URL-encoding, Chrome, Firefox, and Safari will URL-encode `location.search` and `location.hash`, while IE11 and Microsoft Edge (pre-Chromium) will not URL-encode these sources. If your data gets URL-encoded before being processed, then an XSS attack is unlikely to work.

### Testing JavaScript execution sinks
Testing JavaScript execution sinks for DOM-based XSS is a little harder. With these sinks, your input doesn't necessarily appear anywhere within the DOM, so you can't search for it. Instead you'll need to use the JavaScript debugger to determine whether and how your input is sent to a sink.

For each potential source, such as `location`, you first need to find cases within the page's JavaScript code where the source is being referenced. In Chrome's developer tools, you can use `Control+Shift+F` (or `Command+Alt+F` on MacOS) to search all the page's JavaScript code for the source.

Once you've found where the source is being read, you can use the JavaScript debugger to add a break point and follow how the source's value is used. You might find that the source gets assigned to other variables. If this is the case, you'll need to use the search function again to track these variables and see if they're passed to a sink. When you find a sink that is being assigned data that originated from the source, you can use the debugger to inspect the value by hovering over the variable to show its value before it is sent to the sink. Then, as with HTML sinks, you need to refine your input to see if you can deliver a successful XSS attack

### Testing for DOM XSS using DOM Invader
Identifying and exploiting DOM XSS in the wild can be a tedious process, often requiring you to manually trawl through complex, minified JavaScript. If you use Burp's browser, however, you can take advantage of its built-in DOM Invader extension, which does a lot of the hard work for you.

![](dom-invader-innerhtml-sink.png)

## Exploiting DOM XSS with different sources and sinks
* In principle, a website is vulnerable to DOM-based cross-site scripting if there is an executable path via which data can propagate from source to sink
* In practice, different sources and sinks have differing properties and behavior that can affect exploitability, and determine what techniques are necessary
* Additionally, the website's scripts might perform validation or other processing of data that must be accommodated when attempting to exploit a vulnerability
* There are a variety of sinks that are relevant to DOM-based vulnerabilities

```python
# jQuery Sink functions
add() after() append() animate() insertAfter() insertBefore() before() html() prepend() replaceAll() replaceWith() wrap() wrapInner() wrapAll() has() constructor() init() index() jQuery.parseHTML() $.parseHTML()

# Main sinks for DOM-XSS
document.write() document.writeln() document.domain element.innerHTML element.outerHTML element.insertAdjacentHTML element.onevent
```

* The `document.write` sink works with `script` elements, so you can use a simple payload

```python
document.write('... <script>alert(document.domain)</script> ...');
```

* The `innerHTML` sink doesn't accept `script` elements on any modern browser, nor will `svg onload` events fire. This means you will need to use alternative elements like `img` or `iframe`. Event handlers such as `onload` and `onerror` can be used in conjunction with these elements

```python
element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'
```

### Sources and sinks in third-party dependencies
Modern web applications are typically built using a number of third-party libraries and frameworks, which often provide additional functions and capabilities for developers. It's important to remember that some of these are also potential sources and sinks for DOM XSS.

#### DOM XSS in jQuery
* If a JavaScript library such as jQuery is being used, look out for sinks that can alter DOM elements on the page
* For instance, jQuery's `attr()` function can change the attributes of DOM elements
* If data is read from a user-controlled source like the URL, then passed to the `attr()` function, then it may be possible to manipulate the value sent to cause XSS

```python
$(function() { 
	$('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```

* You can exploit this by modifying the URL so that the `location.search` source contains a malicious JavaScript URL
* After the page's JavaScript applies this malicious URL to the back link's `href`, clicking on the back link will execute it

```python
?returnUrl=javascript:alert(document.domain)
```

* Another potential sink to look out for is jQuery's `$()` selector function, which can be used to inject malicious objects into the DOM
* jQuery used to be extremely popular, and a classic DOM XSS vulnerability was caused by websites using this selector in conjunction with the `location.hash` source for animations or auto-scrolling to a particular element on the page
* This behavior was often implemented using a vulnerable `hashchange` event handler

```python
$(window).on('hashchange', function() { 
	var element = $(location.hash); 
	element[0].scrollIntoView(); 
});
```

* As the `hash` is user controllable, an attacker could use this to inject an XSS vector into the `$()` selector sink
* **More recent versions of jQuery have patched this particular vulnerability by preventing you from injecting HTML into a selector when the input begins with a hash character (`#`)**
* However, you may still find vulnerable code in the wild
* To actually exploit this classic vulnerability, you'll need to find a way to trigger a `hashchange` event without user interaction
* One of the simplest ways of doing this is to deliver your exploit via an `iframe`

```python
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

* **Even newer versions of jQuery can still be vulnerable via the `$()` selector sink, provided you have full control over its input from a source that doesn't require a `#` prefix**

## DOM XSS combined with reflected and stored data
* Some pure DOM-based vulnerabilities are self-contained within a single page
* If a script reads some data from the URL and writes it to a dangerous sink, then the vulnerability is entirely client-side
* However, sources aren't limited to data that is directly exposed by browsers - they can also originate from the website
* For example, websites often reflect URL parameters in the HTML response from the server
* This is commonly associated with normal XSS, but it can also lead to reflected DOM XSS vulnerabilities
* In a reflected DOM XSS vulnerability, the server processes data from the request, and echoes the data into the response
* The reflected data might be placed into a JavaScript string literal, or a data item within the DOM, such as a form field
* A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink

```python
eval('var data = "reflected string"');
```

* Websites may also store data on the server and reflect it elsewhere
* In a stored DOM XSS vulnerability, the server receives data from one request, stores it, and then includes the data in a later response
* A script within the later response contains a sink which then processes the data in an unsafe way

```python
element.innerHTML = comment.author
```

## How to prevent XSS attacks
Preventing cross-site scripting is trivial in some cases but can be much harder depending on the complexity of the application and the ways it handles user-controllable data.

In general, effectively preventing XSS vulnerabilities is likely to involve a combination of the following measures:

- **Filter input on arrival.** At the point where user input is received, filter as strictly as possible based on what is expected or valid input.
- **Encode data on output.** At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.
- **Use appropriate response headers.** To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the `Content-Type` and `X-Content-Type-Options` headers to ensure that browsers interpret the responses in the way you intend.
- **Content Security Policy.** As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.

## Exploiting cross-site scripting to steal cookies
* Most web applications use cookies for session handling
* You can exploit cross-site scripting vulnerabilities to send the victim's cookies to your own domain, then manually inject the cookies into the browser and impersonate the victim
* Limitations
	* The victim might not be logged in
	- Many applications hide their cookies from JavaScript using the `HttpOnly` flag
	- Sessions might be locked to additional factors like the user's IP address
	- The session might time out before you're able to hijack it

## Exploiting cross-site scripting to capture passwords
* These days, many users have password managers that auto-fill their passwords
* You can take advantage of this by creating a password input, reading out the auto-filled password, and sending it to your own domain
* This technique avoids most of the problems associated with stealing cookies, and can even gain access to every other account where the victim has reused the same password
* The primary disadvantage of this technique is that it only works on users who have a password manager that performs password auto-fill

## Exploiting cross-site scripting to perform [CSRF](https://portswigger.net/web-security/csrf)
* Depending on the site you're targeting, you might be able to make a victim send a message, accept a friend request, commit a backdoor to a source code repository, or transfer some Bitcoin
* Some websites allow logged-in users to change their email address without re-entering their password
* If you've found an XSS vulnerability, you can make it trigger this functionality to change the victim's email address to one that you control, and then trigger a password reset to gain access to the account

## XSS in HTML tag attributes
* When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tag, and introduce a new one

```python
"><script>alert(document.domain)</script>
```

* More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears
* Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler

```python
" autofocus onfocus=alert(document.domain) x="
```

* The above payload creates an `onfocus` event that will execute JavaScript when the element receives the focus, and also adds the `autofocus` attribute to try to trigger the `onfocus` event automatically without any user interaction. Finally, it adds `x="` to gracefully repair the following markup.
* Sometimes the XSS context is into a type of HTML tag attribute that itself can create a scriptable context
* Here, you can execute JavaScript without needing to terminate the attribute value
* For example, if the XSS context is into the `href` attribute of an anchor tag, you can use the `javascript` pseudo-protocol to execute script

```python
<a href="javascript:alert(document.domain)">
```

* You might encounter websites that encode angle brackets but still allow you to inject attributes
* Sometimes, these injections are possible even within tags that don't usually fire events automatically, such as a canonical tag
* You can exploit this behavior using access keys and user interaction on Chrome
* Access keys allow you to provide keyboard shortcuts that reference a specific element
* The `accesskey` attribute allows you to define a letter that, when pressed in combination with other keys (these vary across different platforms), will cause events to fire

## XSS into JavaScript
When the XSS context is some existing JavaScript within the response, a wide variety of situations can arise, with different techniques necessary to perform a successful exploit

### Terminating the existing script

```python
<script> 
... 
	var input = 'controllable data here';
... 
</script>
```

```python
</script>
<img src=1 onerror=alert(document.domain)>
```

* The reason this works is that the browser first performs HTML parsing to identify the page elements including blocks of script, and only later performs JavaScript parsing to understand and execute the embedded scripts
* The above payload leaves the original script broken, with an unterminated string literal
* But that doesn't prevent the subsequent script being parsed and executed in the normal way

### Breaking out of a JavaScript string
* In cases where the XSS context is inside a quoted string literal, it is often possible to break out of the string and execute JavaScript directly
* It is essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing
* Some useful ways of breaking out

```python
'-alert(document.domain)-' 
';alert(document.domain)//
```

* Some applications attempt to prevent input from breaking out of the JavaScript string by escaping any single quote characters with a backslash
* A backslash before a character tells the JavaScript parser that the character should be interpreted literally, and not as a special character such as a string terminator
* In this situation, applications often make the mistake of failing to escape the backslash character itself
* This means that an attacker can use their own backslash character to neutralize the backslash that is added by the application

```python
';alert(document.domain)//
\';alert(document.domain)//
```

```python
\';alert(document.domain)//
\\';alert(document.domain)//
```

* Some websites make XSS more difficult by restricting which characters you are allowed to use
* This can be on the website level or by deploying a **WAF** that prevents your requests from ever reaching the website
* In these situations, you need to experiment with other ways of calling functions which bypass these security measures
* **One way of doing this is to use the `throw` statement with an exception handler**
* This enables you to pass arguments to a function without using parentheses
* The following code assigns the `alert()` function to the global exception handler and the `throw` statement passes the `1` to the exception handler (in this case `alert`)

```python
onerror=alert;throw 1
```

* There are multiple ways of using this technique to call [functions without parentheses](https://portswigger.net/research/xss-without-parentheses-and-semi-colons)

### Making use of HTML-encoding
* When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around some input filters
* When the browser has parsed out the HTML tags and attributes within a response, it will perform HTML-decoding of tag attribute values before they are processed any further
* If the server-side application blocks or sanitizes certain characters that are needed for a successful XSS exploit, you can often bypass the input validation by HTML-encoding those characters

```python
<a href="#" onclick="... var input='controllable data here'; ...">
```

* And the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script

```python
&apos;-alert(document.domain)-&apos;
```

* The `&apos;` sequence is an HTML entity representing an apostrophe or single quote. Because the browser HTML-decodes the value of the `onclick` attribute before the JavaScript is interpreted, the entities are decoded as quotes, which become string delimiters, and so the attack succeeds

### XSS in JavaScript template literals
* JavaScript template literals are string literals that allow embedded JavaScript expressions
* The embedded expressions are evaluated and are normally concatenated into the surrounding text
* Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the `${...}` syntax

```python
document.getElementById('message').innerText = `Welcome,
${user.displayName}.`;
```

```python
<script> 
...
	var input = `controllable data here`; 
... 
</script>
```

```python
${alert(document.domain)}
```


## Client-side template injection
* Arise when applications using a client-side template framework dynamically embed user input in web pages
* When rendering a page, the framework scans it for template expressions and executes any that it encounters
* An attacker can exploit this by supplying a malicious template expression that launches a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) (XSS) attack

## What is the AngularJS sandbox?
* A mechanism that prevents access to potentially dangerous objects, such as `window` or `document`, in AngularJS template expressions
* Also prevents access to potentially dangerous properties, such as `__proto__`
* Despite not being considered a security boundary by the AngularJS team, the wider developer community generally thinks otherwise
* Although bypassing the sandbox was initially challenging, security researchers have discovered numerous ways of doing so
* As a result, it was eventually **removed from AngularJS in version 1.6**
* However, many legacy applications still use older versions of AngularJS and may be vulnerable as a result

## How does the AngularJS sandbox work?
* The sandbox works by parsing an expression, rewriting the JavaScript, and then using various functions to test whether the rewritten code contains any dangerous objects
* For example, the `ensureSafeObject()` function checks whether a given object references itself
* This is one way to detect the `window` object, for example
* The `Function` constructor is detected in roughly the same way, by checking whether the constructor property references itself
* The `ensureSafeMemberName()` function checks each property access of the object and, if it contains dangerous properties such as `__proto__` or `__lookupGetter__`, the object will be blocked
* The `ensureSafeFunction()`function prevents `call()`, `apply()`, `bind()`, or `constructor()` from being called

## How does an AngularJS sandbox escape work?
* A sandbox escape involves tricking the sandbox into thinking the malicious expression is harmless
* The most well-known escape uses the modified `charAt()` function globally within an expression

```python
'a'.constructor.prototype.charAt=[].join
```

* When it was initially discovered, AngularJS did not prevent this modification
* The attack works by overwriting the function using the `[].join` method, which causes the `charAt()` function to return all the characters sent to it, rather than a specific single character
* Due to the logic of the `isIdent()` function in AngularJS, it compares what it thinks is a single character against multiple characters
* As single characters are always less than multiple characters, the `isIdent()` function always returns true, as demonstrated by the following example

```python
isIdent = function(ch) { 
	return ('a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || '_' === ch || ch === '$'); 
} 
isIdent('x9=9a9l9e9r9t9(919)')
```

* Once the `isIdent()` function is fooled, you can inject malicious JavaScript
* For example, an expression such as `$eval('x=alert(1)')` would be allowed because AngularJS treats every character as an identifier
* Note that we need to use AngularJS's `$eval()` function because overwriting the `charAt()` function will only take effect once the sandboxed code is executed

### Constructing an advanced AngularJS sandbox escape
* A site may prevent you from using double or single quotes
* In this situation, you need to use functions such as `String.fromCharCode()` to generate your characters
* Although AngularJS prevents access to the `String` constructor within an expression, you can get round this by using the constructor property of a string instead
* This obviously requires a string, so to construct an attack like this, you would need to find a way of creating a string without using single or double quotes
* Fortunately, we can use the `orderBy` filter instead when `$eval()` does not work

```python
[123]|orderBy:'Some string'
```

* Normally, this is a bitwise `OR` operation, but in AngularJS it indicates a filter operation
* In the code above, we are sending the array `[123]` on the left to the `orderBy` filter on the right
* The colon signifies an argument to send to the filter, which in this case is a string
* The `orderBy` filter is normally used to sort an object, but it also accepts an expression, which means we can use it to pass a payload

## How does an AngularJS CSP bypass work?
* Work in a similar way to standard sandbox escapes, but usually involve some HTML injection
* When the CSP mode is active in AngularJS, it parses template expressions differently and avoids using the `Function` constructor
* This means the standard sandbox escape described above will no longer work
* Depending on the specific policy, the CSP will block JavaScript events
* However, AngularJS defines its own events that can be used instead
* When inside an event, AngularJS defines a special `$event` object, which simply references the browser event object
* You can use this object to perform a CSP bypass
* On Chrome, there is a special property on the `$event/event` object called `path`
* This property contains an array of objects that causes the event to be executed
* The last property is always the `window` object, which we can use to perform a sandbox escape
* By passing this array to the `orderBy` filter, we can enumerate the array and use the last element (the `window` object) to execute a global function, such as `alert()`

```python
<input autofocus ng-focus="$event.path|orderBy:'[].constructor.from([1],alert)'">
```

* Notice that the `from()` function is used, which allows you to convert an object to an array and call a given function (specified in the second argument) on every element of that array
* We cannot call the function directly because the AngularJS sandbox would parse the code and detect that the `window` object is being used to call a function
* Using the `from()` function instead effectively hides the `window` object from the sandbox, allowing us to inject malicious code

### Bypassing a CSP with an AngularJS sandbox escape

```python
[1].map(alert)
```

`map()` accepts a function as an argument and will call it for each item in the array. This will bypass the sandbox because the reference to the `alert()` function is being used without explicitly referencing the `window`

## How to prevent client-side template injection vulnerabilities
To prevent client-side template injection vulnerabilities, avoid using untrusted user input to generate templates or expressions. If this is not practical, consider filtering out template expression syntax from user input prior to embedding it within client-side templates.

Note that HTML-encoding is not sufficient to prevent client-side template injection attacks, because frameworks perform an HTML-decode of relevant content prior to locating and executing template expressions.

## Resources
* [Cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) + filter bypasses
* Call [functions](https://portswigger.net/research/xss-without-parentheses-and-semi-colons) without parentheses
* [Prevent XSS](https://portswigger.net/web-security/cross-site-scripting/preventing)

---

## Mitigating XSS attacks using CSP
* The following directive will only allow scripts to be loaded from the [same origin](https://portswigger.net/web-security/cors/same-origin-policy) as the page itself

```python
script-src 'self'
```

* The following directive will only allow scripts to be loaded from a specific domain

```python
script-src https://scripts.normal-website.com
```

Care should be taken when allowing scripts from external domains. If there is any way for an attacker to control content that is served from the external domain, then they might be able to deliver an attack. For example, content delivery networks (CDNs) that do not use per-customer URLs, such as `ajax.googleapis.com`, should not be trusted, because third parties can get content onto their domains.

In addition to whitelisting specific domains, content security policy also provides two other ways of specifying trusted resources: nonces and hashes:
- The CSP directive can specify a nonce (a random value) and the same value must be used in the tag that loads a script. If the values do not match, then the script will not execute. To be effective as a control, the nonce must be securely generated on each page load and not be guessable by an attacker.
- The CSP directive can specify a hash of the contents of the trusted script. If the hash of the actual script does not match the value specified in the directive, then the script will not execute. If the content of the script ever changes, then you will of course need to update the hash value that is specified in the directive.

It's quite common for a CSP to block resources like `script`. However, many CSPs do allow image requests. This means you can often use `img` elements to make requests to external servers in order to disclose [CSRF](https://portswigger.net/web-security/csrf) tokens, for example.

Some browsers, such as Chrome, have built-in [dangling markup](https://portswigger.net/web-security/cross-site-scripting/dangling-markup) mitigation that will block requests containing certain characters, such as raw, unencoded new lines or angle brackets.

Some policies are more restrictive and prevent all forms of external requests. However, it's still possible to [get round these restrictions by eliciting some user interaction](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup). To bypass this form of policy, you need to inject an HTML element that, when clicked, will store and send everything enclosed by the injected element to an external server.

## Mitigating dangling markup attacks using CSP
The following directive will only allow images to be loaded from the same origin as the page itself: `img-src 'self'`

The following directive will only allow images to be loaded from a specific domain: `img-src https://images.normal-website.com`

Note that these policies will prevent some dangling markup exploits, because an easy way to capture data with no user interaction is using an `img` tag. However, it will not prevent other exploits, such as those that inject an anchor tag with a dangling `href` attribute.

## Bypassing CSP with policy injection
You may encounter a website that reflects input into the actual policy, most likely in a `report-uri` directive. If the site reflects a parameter that you can control, you can inject a semicolon to add your own CSP directives. Usually, this `report-uri` directive is the final one in the list. This means you will need to overwrite existing directives in order to exploit this vulnerability and bypass the policy.

Normally, it's not possible to overwrite an existing `script-src` directive. However, Chrome recently introduced the `script-src-elem` directive, which allows you to control `script` elements, but not events. Crucially, this new directive allows you to [overwrite existing `script-src` directives](https://portswigger.net/research/bypassing-csp-with-policy-injection). Using this knowledge, you should be able to solve the following lab.

## Protecting against [clickjacking](https://portswigger.net/web-security/clickjacking) using CSP
The following directive will only allow the page to be framed by other pages from the same origin: `frame-ancestors 'self'`

The following directive will prevent framing altogether: `frame-ancestors 'none'`

Using content security policy to prevent clickjacking is more flexible than using the X-Frame-Options header because you can specify multiple domains and use wildcards. For example: `frame-ancestors 'self' https://normal-website.com https://*.robust-website.com`

CSP also validates each frame in the parent frame hierarchy, whereas `X-Frame-Options` only validates the top-level frame.

Using CSP to protect against clickjacking attacks is recommended. You can also combine this with the `X-Frame-Options` header to provide protection on older browsers that don't support CSP, such as Internet Explorer.

## Resources
* [Bypass restricitons](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup)