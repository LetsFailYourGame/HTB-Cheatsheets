## **FFUF**

### Fuzzing
* Best to enumerate file extension first

```bash
ffuf -u http://<domain>/FUZZ -e .php -w <wordlist>:FUZZ -c -recursion -recursion-depth 1
```

### Subdomains
* Make use of VHosts to discover local / not public subdomains by providing a header -H which is beeing fuzzed
* When found add to /etc/hosts

```bash
ffuf -u http://<domain>/ -w <wordlist>:FUZZ -c -H 'Host: FUZZ.<domain>'
```

### Filter
* Filter wrong package size for example with -fs 900
```bash
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response
```
```bash
FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges
```

### Finding GET / POST parameters
* Filter for wrong response size with -fs
* Try POST and GET both sometimes deliver different results
* Use curl to check the response
  *  `curl -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded' <url>`

```bash
ffuf -u http://<domain>/example.php?FUZZ=anything -w <wordlist>:FUZZ -c -fs XXX
```

```bash
ffuf -u http://<domain>/example.php?FUZZ=anything -w <wordlist>:FUZZ -c -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs XXX
```

### Fuzzing parameters
* Maybe create own wordlist containing ids via bash / python

```bash
ffuf -u http://<domain>/example.php -w <wordlist>:FUZZ -c -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs XXX
```
