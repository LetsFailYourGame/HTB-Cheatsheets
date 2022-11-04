## Detect number of columns
* First we need to find the number of columns selected by the server
	-   Using `ORDER BY`
	-   Using `UNION`

#### Using ORDER BY
*  We can start with `order by 1`, sort by the first column, and succeed
* Then we will do `order by 2` and then `order by 3` until we reach a number that returns an error; or the page does not show any output
* If we failed at `order by 4`, this means the table has three columns

```sql
' order by 1-- -
```

```sql
' order by 2-- -
```

#### Using UNION
* Do the same thing as with ORDER BY
* Order by works until it errors, UNION errors until it succeeds

```sql
cn' UNION select 1,2,3,4-- -
```

## Location of Injection
* While a query may return multiple columns, the web application may only display some of them
* This is why we need to determine which columns are printed to the page, to determine where to place our injection

![[../../Screenshots/ports_columns_correct.png]]

```sql
cn' UNION select 1,@@version,3,4-- -
```

![[../../Screenshots/db_version_1.jpg]]
