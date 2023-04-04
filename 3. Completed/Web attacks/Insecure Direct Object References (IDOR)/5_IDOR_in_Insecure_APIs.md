## IDOR in Insecure APIs
* While `IDOR Information Disclosure Vulnerabilities` allow us to read various types of resources, `IDOR Insecure Function Calls` enable us to call APIs or execute functions as another user
	* Can be used to change another user's private information, reset another user's password, or even buy items using another user's payment information

## Identifying Insecure APIs
![](web_attacks_idor_update_request.jpg)

* The page is sending a `PUT` request to the `/profile/api.php/profile/1` API endpoint
* `PUT` requests are usually used in APIs to update item details, while `POST` is used to create new items, `DELETE` to delete items, and `GET` to retrieve item details

```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

* Hidden parameters 
	* uuid
	* uid
	* role
* Access privileges set (e.g. `role`) on the client-side, in the form of our `Cookie: role=employee` cookie

## Exploiting Insecure APIs
* We can change the `full_name`, `email`, and `about` parameters, as these are the ones under our control in the HTML form in the `/profile`
* There are a few things we could try in this case:
	1.  Change our `uid` to another user's `uid`, such that we can take over their accounts
	2.  Change another user's details, which may allow us to perform several web attacks
	3.  Create new users with arbitrary details, or delete existing users
	4.  Change our role to a more privileged role (e.g. `admin`) to be able to perform more actions
* Lets try changing the uid

 ![](web_attacks_idor_uid_mismatch.jpg)

* The application seems to compare the requested `uid` to the API endpoint (`/1`)
* This means that a form of access control on the back-end prevents us from arbitrarily changing some JSON parameters
* We can fix that by calling `/profile/api.php/profile/2`, and change `"uid": 2` to avoid the previous `uid mismatch`

![](web_attacks_idor_uuid_mismatch.jpg)

* The web application appears to be checking if the `uuid` value we are sending matches the user's `uuid`
* Test if we can create a new user with a `POST` request to the API endpoint

![](web_attacks_idor_create_new_user_1.jpg)

* Error: `Creating new employees is for admins only`
* Try to change our `role` to `admin`/`administrator` to gain higher privileges
* Without knowing a valid `role` name, we get `Invalid role`
* However `GET` method returns information about other users

```http
GET /profile/api.php/profile/5 HTTP/1.1
Host: 161.35.168.151:30135
Content-Length: 208
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Content-type: application/json
Accept: */*
Origin: http://161.35.168.151:30135
Referer: http://161.35.168.151:30135/profile/index.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: role=employee
Connection: close

{"uid":5,"uuid":"40f5888b67c748df7efba008e7c2f9d2","role":"employee","full_name":"Amy Lindon","email":"a_lindon@employees.htb","about":"A Release is like a boat. 80% of the holes plugged is not good enough."}
```