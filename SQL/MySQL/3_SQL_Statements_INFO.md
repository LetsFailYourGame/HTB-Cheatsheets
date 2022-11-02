## INSERT Statement
* Used to add new records to a given table

```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
```

* Above requires user to fill in all values for all columns

```sql
mysql> INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');

Query OK, 1 row affected (0.00 sec)
```

* Skip filling columns with default values by specifying the column names to insert values into a table selectively

```sql
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
```

```sql
mysql> INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');

Query OK, 1 row affected (0.00 sec)
```

* Insert multiple records at once

```sql
mysql> INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');

Query OK, 2 rows affected (0.00 sec)
Records: 2  Duplicates: 0  Warnings: 0
```

## SELECT Statement
```sql
SELECT * FROM table_name;
```

```sql
SELECT column1, column2 FROM table_name;
```

* `*` - Wildcard

```sql
mysql> SELECT * FROM logins;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)


mysql> SELECT username,password FROM logins;

+---------------+------------+
| username      | password   |
+---------------+------------+
| admin         | p@ssw0rd   |
| administrator | adm1n_p@ss |
| john          | john123!   |
| tom           | tom123!    |
+---------------+------------+
4 rows in set (0.00 sec)
```

## DROP Statement
```sql
mysql> DROP TABLE logins;

Query OK, 0 rows affected (0.01 sec)


mysql> SHOW TABLES;

Empty set (0.00 sec)
```

## ALTER Statement
* Change the name of any table and any of its fields or to delete or add a new column to an existing table

```sql
mysql> ALTER TABLE logins ADD newColumn INT;

Query OK, 0 rows affected (0.01 sec)
```

* Rename column

```sql
mysql> ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;

Query OK, 0 rows affected (0.01 sec)
```

* Change datatype

```sql
mysql> ALTER TABLE logins MODIFY oldColumn DATE;

Query OK, 0 rows affected (0.01 sec)
```

* Drop a column

```sql
mysql> ALTER TABLE logins DROP oldColumn;

Query OK, 0 rows affected (0.01 sec)
```

## UPDATE Statement
* Can be used to update specific records in a table base on conditions

```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

```sql
mysql> UPDATE logins SET password = 'change_password' WHERE id > 1;

Query OK, 3 rows affected (0.00 sec)
Rows matched: 3  Changed: 3  Warnings: 0


mysql> SELECT * FROM logins;

+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:47:16 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```