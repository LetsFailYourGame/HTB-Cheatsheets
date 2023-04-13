![](./Screenshots/Pasted%20image%2020230328001725.png)

* Run amass
```sh
$ amass enum --passive -d <DOMAIN>
# Or check for Zonetransfers and alt
```

* Run assetfinder
```sh
$ assetfinder example.com
```

* Run subfinder
```sh
$ subfinder -d domain.com -all -silent
```

* Run gau
```sh
gau --subs example.com | unfurl -u domains
```

* Run CommonSpeak2
```python
scope = '<DOMAIN>'
wordlist = open('./commonspeak2.txt').read().split('\n')

for word in wordlist:
    if not word.strip(): 
        continue
    print('{}.{}\n'.format(word.strip(), scope))
```

* Run altdns
```sh
$ altdns -i subdomain.mass.strip -o subdomain.altdns -w /usr/share/seclists/Discovery/DNS/altdns.txt 
```

* Use all subdomains in massdns
```sh
$ massdns -s 15000 -t A -o S -r /usr/share/seclists/Discovery/DNS/resolver.txt --flush subdomain.list >> subdomain.mass
```

* Run github-subdomains (if nessecarry)
```sh
$ github-subdomains -d example.com -t tokens.txt -o output.txt
```

* Run ctfr
```sh
$ python3 ctfr.py -d domain.com
```

* Use `httpx` to get alive subdomains

```sh
$ subfinder -d hackerone.com -silent| httpx -title -tech-detect -status-code
```

* Use `Aquatone` to get a flyover of all pages





