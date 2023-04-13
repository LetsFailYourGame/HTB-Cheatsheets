* Use ParamSpider to generate URLs

```sh
$ python3 paramspider.py --domain X --exclude png,jpg 
```

* Use openredirex to find redirects

```sh
$ python3 openredirex.py -l paramspider_file -p payloads.txt --keyword=FUZZ
```

* Use [Burp](https://portswigger.net/support/using-burp-to-test-for-open-redirections)
* Use waybackruls onliner

```sh
export target=""
export rdto=""
```

```sh
waybackurls $target | grep -a -i \=http | qsreplace $rdto | while read host do;do curl -s -L $host -I| grep $rdto && echo -e "$host \033[0;31mVulnerable\n" ;done
```

* [Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
