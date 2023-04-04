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
$ python altdns.py -i input_domains.txt -o ./output/path -w wordlist
```

* Use all subdomains in massdns
```python
#python3

import json
import subprocess

RESOLVERS_PATH = '/path/to/resolvers.txt'

def _exec_and_readlines(cmd, domains):

    domains_str = bytes('\n'.join(domains), 'ascii')
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.PIPE)
    stdout, stderr = proc.communicate(input=domains_str)

    return [j.decode('utf-8').strip() for j in stdout.splitlines() if j != b'\n']

def get_massdns(domains):
    massdns_cmd = [
        'massdns',
        '-s', '15000',
        '-t', 'A',
        '-o', 'J',
        '-r', RESOLVERS_PATH,
        '--flush'
    ]

    processed = []

    for line in _exec_and_readlines(massdns_cmd, domains):
        if not line:
            continue

        processed.append(json.loads(line.strip()))

    return processed

print(get_massdns(['example.com', 'sub.example.com']))
```

* Run github-subdomains (if nessecarry)
```sh
$github-subdomains -d example.com -t tokens.txt -o output.txt
```

* Run ctfr
```sh
$ python3 ctfr.py -d domain.com
```

* Use Aquatone to get a flyover of all pages





