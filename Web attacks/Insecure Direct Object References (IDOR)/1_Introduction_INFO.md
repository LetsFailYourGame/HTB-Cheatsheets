## IDOR
* Insecure Direct Object References (IDOR)
* One of the `most common vulnerabilities`
* Occur when a web application exposes a direct reference to an object
* File, Database resource which the end-user can directly control to obtain access to other similar objects
* Example
	* User requests access to recently uploaded file (`download.php?file_id=123`)
	* Link directly references the file with (`file_id=123`)
	* We may be able to access any file by sending a request with its `file_id`

## What Makes an IDOR Vulnerability
* Exposing a direct reference to an internal object or resource is not a vulnerability in itself
* May make it possible to exploit another vulnerability: a `weak access control system`
* Many web applications restrict users from accessing resources by restricting them from accessing the pages, functions, and APIs that can retrieve these resources
	* However, what would happen if a user somehow got access to these pages (e.g., through a shared/guessed link)
	* Would they still be able to access the same resources by simply having the link to access them?
	* If a web application did not have an access control system on the back-end that compares the user's authentication to the resource's access list, they might be able to
* Role-Based Access Control ([RBAC](https://en.wikipedia.org/wiki/Role-based_access_control)) system
* Main takeaway is that `an IDOR vulnerability mainly exists due to the lack of an access control on the back-end`

## Impact of IDOR Vulnerabilities
* Most basic example of an IDOR vulnerability is accessing private files and resources of other users that should not be accessible
	* Personnel files or credit card data, which is known as `IDOR Information Disclosure Vulnerabilities`
* Vulnerability may even allow the modification or deletion of other users' data, which may lead to a complete account takeover
* Elevation of user privileges from a standard user to an administrator user, with `IDOR Insecure Function Calls`
	* API's or URL parameters for admin-only functions