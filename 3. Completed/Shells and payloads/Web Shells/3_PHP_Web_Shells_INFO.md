## Bypassing the File Type Restriction
* Upload [PHP shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell) to website and capture request

![](burp.png)

* Change Content-type from `application/x-php` to `image/gif` to trick the application
* Navigate to the file `/images/vendor/connect.php` and we get a shell like before

![](web_shell_now.png)

* Limitations
	- Web applications sometimes automatically delete files after a pre-defined period
	- Limited interactivity with the operating system in terms of navigating the file system, downloading and uploading files, chaining commands together may not work (ex. `whoami && hostname`), slowing progress, especially when performing enumeration -Potential instability through a non-interactive web shell
	- Greater chance of leaving behind proof that we were successful in our attack