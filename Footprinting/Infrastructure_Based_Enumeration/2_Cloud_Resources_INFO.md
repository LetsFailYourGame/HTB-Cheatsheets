### Company Hosted Servers

```sh
$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done

blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
www.inlanefreight.com 10.129.127.33
s3-website-us-west-2.amazonaws.com 10.129.95.250
```

* Often, cloud storage is added to the DNS list when used for administrative purposes by other employees
* We have already seen that one IP address belongs to the `s3-website-us-west-2.amazonaws.com` server
	* The easiest and most used way to find such cloud storage is Google search
	* `intext:<comany_name> inurl:<cloud_provider>.com`
	* Information like text documents, presentations, codes etc. can be found in PDF's or source code of the web pages, images, JS, or CSS
* Third-party providers such as [domain.glass](https://domain.glass/) can tell us a lot about the infrastructure
	* As a possible side effect, we can also see if Cloudflare is used (when classified as `Safe`)
* Another useful provider is [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
	* Discover AWS, Azure, and GCP cloud storage
	* We can find leaked private and public keys for example