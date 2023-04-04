## Basic LFI
* User can set the Langauge 

![](basic_lfi_lang.png)

* If we select a language by clicking on it (e.g. `Spanish`), we see that the content text changes to spanish
* `http://<SERVER_IP>:<PORT>/index.php?language=es.php`

![](basic_lfi_es.png)

* Two common readable files that are available on most back-end servers are `/etc/passwd` on Linux and `C:\Windows\boot.ini` on Windows
* Change from `es` to `/etc/passwd`
* `http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd`

![](basic_lfi_lang_passwd.png)

## Path Traversal
* In the earlier example, we read a file by specifying its `absolute path` (e.g. `/etc/passwd`)
* This would work if the whole input was used within the `include()` function without any additions

```php
include($_GET['language']);
```

* In this case, if we try to read `/etc/passwd`, then the `include()` function would fetch that file directly
* In many occasions, web developers may append or prepend a string to the `language` parameter
* For example, the `language` parameter may be used for the filename, and may be added after a directory

```php
include("./languages/" . $_GET['language']);
```

* In this case, if we attempt to read `/etc/passwd`, then the path passed to `include()` would be (`./languages//etc/passwd`), and as this file does not exist, we will not be able to read anything
* `http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd`
  ![](traversal_passwd_failed.png)

**Note:** We are only enabling PHP errors on this web application for educational purposes, so we can properly understand how the web application is handling our input. For production web applications, such errors should never be shown. Furthermore, all of our attacks should be possible without errors, as they do not rely on them.

* We can easily bypass this restriction by traversing directories using `relative paths`
* We can add `../` before our file name, which refers to the parent directory
* If the full path of the languages directory is `/var/www/html/languages/`, then using `../index.php` would refer to the `index.php` file on the parent directory (i.e. `/var/www/html/index.php`)
* Go back several directories until we reach the root path (i.e. `/`), and then specify our absolute file path (e.g. `../../../../etc/passwd`), and the file should exist
* `http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/passwd`

![](traversal_passwd.png)

**Tip:** It can always be useful to be efficient and not add unnecessary `../` several times, especially if we were writing a report or writing an exploit. So, always try to find the minimum number of `../` that works and use it. You may also be able to calculate how many directories you are away from the root path and use that many. For example, with `/var/www/html/` we are `3` directories away from the root path, so we can use `../` 3 times (i.e. `../../../`)

## Filename Prefix
* In our previous example, we used the `language` parameter after the directory, so we could traverse the path to read the `passwd` file
* On some occasions, our input may be appended after a different string
* For example, it may be used with a prefix to get the full filename

```php
include("lang_" . $_GET['language']);
```

* In this case, if we try to traverse the directory with `../../../etc/passwd`, the final string would be `lang_../../../etc/passwd`, which is invalid
* `http://<SERVER_IP>:<PORT>/index.php?language=../../../etc/passwd`

![](lfi_another_example1.png)

* As expected, the error tells us that this file does not exist. so, instead of directly using path traversal, we can prefix a `/` before our payload, and this should consider the prefix as a directory, and then we should bypass the filename and be able to traverse directories

![](lfi_another_example_passwd1.png)

**Note:** This may not always work, as in this example a directory named `lang_/` may not exist, so our relative path may not be correct. Furthermore, `any prefix appended to our input may break some file inclusion techniques` we will discuss in upcoming sections, like using PHP wrappers and filters or RFI.

## Appended Extensions
* Another very common example is when an extension is appended to the `language` parameter

```php
include($_GET['language'] . ".php");
```

* This is quite common, as in this case, we would not have to write the extension every time we need to change the language
* This may also be safer as it may restrict us to only including PHP files
* In this case, if we try to read `/etc/passwd`, then the file included would be `/etc/passwd.php`, which does not exist
* `http://<SERVER_IP>:<PORT>/extension/index.php?language=/etc/passwd`

![](lfi_extension_failed.png)

## Second-Order Attacks
* Another common, and a little bit more advanced, LFI attack is a `Second Order Attack`
* This occurs because many web application functionalities may be insecurely pulling files from the back-end server based on user-controlled parameters
* For example, a web application may allow us to download our avatar through a URL like (`/profile/$username/avatar.png`)
* If we craft a malicious LFI username (e.g. `../../../etc/passwd`), then it may be possible to change the file being pulled to another local file on the server and grab it instead of our avatar
* In this case, we would be poisoning a database entry with a malicious LFI payload in our username
* Then, another web application functionality would utilize this poisoned entry to perform our attack (i.e. download our avatar based on username value)