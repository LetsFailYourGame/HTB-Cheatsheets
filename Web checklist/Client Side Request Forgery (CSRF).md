Allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

[Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CSRF%20Injection/README.md)

* Check if **no Anti-CSRF Tokens** are used normaly then vulnerable
* Check if **SameSite cookies** not set to Lax 
* Check **Referer header** is not set
* Check if conditions met
	* There is an action within the application that the attacker has a reason to induce
	* Cookie-based session handling
	* The requests that perform the action do not contain any parameters whose values the attacker cannot determine or guess

![](cross-site%20request%20forgery.svg)


