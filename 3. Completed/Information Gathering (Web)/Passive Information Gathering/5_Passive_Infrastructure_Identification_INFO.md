### [Netcraft](https://www.netcraft.com/)
* Offers information about the servers without even interacting with them
* https://sitereport.netcraft.com

![](Screenshot_2022-10-07_171007.png)

* Interesting details we can observe

| Option              | Description                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| `Background`        | General information about the domain, including the date it was first seen by Netcraft crawlers |
| `Network`           | Information about the netblock owner, hosting company, nameservers, etc                         |
| ``Hosting history`` | Latest IPs used, webserver, and target OS                                                       | 

* We need to pay special attention to the `latest IPs used`
* Sometimes we can spot the `actual IP` address from the webserver before it was placed behind a load balancer, web application firewall, or IDS, allowing us to connect directly to it if the configuration allows it

### Wayback Machine
* Find old versions that may have interesting comments in the source code or files that should not be there

```sh
$ go get github.com/tomnomnom/waybackurls
```

```sh
$ waybackurls -dates https://facebook.com > waybackurls.txt
$ cat waybackurls.txt

2018-05-20T09:46:07Z http://www.facebook.com./
2018-05-20T10:07:12Z https://www.facebook.com/
2018-05-20T10:18:51Z http://www.facebook.com/#!/pages/Welcome-Baby/143392015698061?ref=tsrobots.txt
2018-05-20T10:19:19Z http://www.facebook.com/
2018-05-20T16:00:13Z http://facebook.com
2018-05-21T22:12:55Z https://www.facebook.com
2018-05-22T15:14:09Z http://www.facebook.com
2018-05-22T17:34:48Z http://www.facebook.com/#!/Syerah?v=info&ref=profile/robots.txt
2018-05-23T11:03:47Z http://www.facebook.com/#!/Bin595

<SNIP>
```