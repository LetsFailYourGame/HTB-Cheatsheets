## URL Parameters & APIs
* The very first step of exploiting IDOR vulnerabilities is `identifying Direct Object References`
* Whenever we receive a specific file or resource, we should study the HTTP requests to look for URL parameters or APIs with an object reference (e.g. `?uid=1` or `?filename=file_1.pdf`)
	* Mostly found in `URL parameters` or `APIs` but may also be found in other `HTTP headers`, like `cookies`
* Most basic cases, try incrementing the values (`?uid=2`) or (`?filename=file_2.pdf`)
* We can also use a fuzzing application to try thousands of variations and see if they return any data

## AJAX Calls
* `Unused parameters` or `APIs` in the front-end code in the form of `JavaScript AJAX calls`

```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

* Above function may never be called when we use a non-admin user
* If we locate it in the front-end code, we may test it in different ways to see whether we can call it to perform changes, which would indicate that it is vulnerable to IDOR
* We can do the same with back-end code if we have access to it (e.g., open-source web applications)

## Understand Hashing/Encoding
* If we find such parameters using encoded or hashed values, we may still be able to exploit them if there is no access control system on the back-end
* For example, if we see a reference like (`?filename=ZmlsZV8xMjMucGRm`), we can immediately guess that the file name is `base64` encoded (from its character set), which we can decode to get the original object reference of (`file_123.pdf`)
* Object reference may be hashed, like (`download.php?filename=c81e728d9d4c2f636f067f89cc14862c`)
	* If we look at the source code, we may see what is being hashed before the API call is made

```javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

* We can also try to use hash identifier tools and then hash the filename to see if it matches the used hash

## Compare User Roles
* If we want to perform more advanced IDOR attacks
	* May need to register multiple users and compare their HTTP requests and object references
	* This may allow us to understand how the URL parameters and unique identifiers are being calculated and then calculate them for other users to gather their data
* For example, if we had access to two different users, one of which can view their salary after making the following API call

```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

* The second user may not have all of these API parameters to replicate the call and should not be able to make the same call as `User1`
* However, with these details at hand, we can try repeating the same API call while logged in as `User2` to see if the web application returns anything