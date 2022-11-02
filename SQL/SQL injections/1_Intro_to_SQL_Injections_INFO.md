## Use of SQL in Web Applications
* With `php` we can connect to our database and start using `MySQL`

```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

* Print all returned results in new lines

```php
while($row = $result->fetch_assoc() ){
	echo $row["name"]."<br>";
}
```

* Usually, users give input to a website which then retrieves the data from a database

```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

**Note** `If we use user-input within an SQL query, and if not securely coded, it may cause a variety of issues, like SQL Injection vulnerabilities.`

## What is an Injection?
* When user input is passed directly to the SQL query without sanitization
* Refers to the removal of any special characters in user-input, in order to break any injection attempts

## SQL Injection
```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

* Normally, the `searchInput` would be inputted to complete the query
* So, if we input `admin`, it becomes `'%admin'` or  `'%SHOW DATABASES;'`
* As there is no sanitization, we can add a single quote (`'`), which will end the user-input field, and after it, we can write actual SQL code
* For example, `1'; DROP TABLE users;`

```php
'%1'; DROP TABLE users;'
```

```sql
select * from logins where username like '%1'; DROP TABLE users;'
```

## Syntax Errors
```php
Error: near line 1: near "'": syntax error
```

*  Because of the last trailing character, where we have a single extra quote (`'`) that is not closed
* In this case, we had only one trailing character, as our input from the search query was near the end of the SQL query
* However, the user input usually goes in the middle of the SQL query, and the rest of the original SQL query comes after it
* So we must ensure that the new query is valid
* We accomplish this by using comments, in the next section

## Types of SQL Injections
* Depending on where the in input is retrieved, we have a different categorie of injection

![[../../Screenshots/types_of_sqli.jpg]]

* `In-band`
	* Output of both the intended and the new query may be printed directly on the front end, and we can directly read it
	* `Union Based` 
		* We may have to specify the exact location, 'i.e., column', which we can read
		* Query will direct the output to be printed there
	* `Error Based`
		* Used when we can get the `PHP` or `SQL` errors in the front-end
		* We may intentionally cause an SQL error that returns the output of our query
* `Blind`
	* We may not get the output printed, so we may utilize SQL logic to retrieve the output character by character
	* `Boolean Based`
		* Use conditional statements to control whether the page returns any output at all, 'i.e., original query response,' if our conditional statement returns `true`
	* `Time Based`
		* We use SQL conditional statements that delay the page response if the conditional statement returns `true` using the `Sleep()` function
* `Out-of-band`
	* We may not have direct access to the output whatsoever
	* We may have to direct the output to a remote location, 'i.e., DNS record,' and then attempt to retrieve it from there