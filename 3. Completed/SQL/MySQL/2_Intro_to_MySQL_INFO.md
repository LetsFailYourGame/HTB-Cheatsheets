## Structured Query Language (SQL)
* Syntax differ from different RDBMS
* Can be used for different actions
	-   Retrieve data
	-   Update data
	-   Delete data
	-   Create new tables and databases
	-   Add / remove users
	-   Assign permissions to these users

## Command Line
* Default MySQL/MariaDB port is (3306)

```sh
# -u <user>
# -p<pass> <either empty or with password but no spaces>
$ mysql -u root -p

Enter password: <password>
...SNIP...

mysql> 
```

```sh
# -h <host>
# -P <port>
$ mysql -u root -h docker.hackthebox.eu -P 3306 -p 

Enter password: 
...SNIP...

mysql> 
```

## Creating a database
```sh
mysql> CREATE DATABASE users;

Query OK, 1 row affected (0.02 sec
```

```sh
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+

mysql> USE users;

Database changed
```

## Tables
```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
```

```sql
mysql> CREATE TABLE logins (
    ->     id INT,
    ->     username VARCHAR(100),
    ->     password VARCHAR(100),
    ->     date_of_joining DATETIME
    ->     );
Query OK, 0 rows affected (0.03 sec)
```

```sql
mysql> SHOW TABLES;

+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
1 row in set (0.00 sec)
```

```sql
mysql> DESCRIBE logins;

+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
4 rows in set (0.00 sec)
```

#### Table Properties
* Auto increment the id by one
* `NOT NULL` means it's a required field and cant be left empty

```sql
    id INT NOT NULL AUTO_INCREMENT,
```

* Use `UNIQUE` to make sure it's a unique value

```sql
username VARCHAR(100) UNIQUE NOT NULL,
```

* Specify a `default` value

```sql
 date_of_joining DATETIME DEFAULT NOW(),
```

* Set the `primary key`

```sql
 PRIMARY KEY (id)
```

* All together

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```

