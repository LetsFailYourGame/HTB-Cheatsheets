## ASPX
* `Active Server Page Extended` (`ASPX`)
*  Type/extension written for [Microsoft's ASP.NET Framework](https://docs.microsoft.com/en-us/aspnet/overview)

## Antak Webshell
* Web shell built-in ASP.Net included within the [Nishang project](https://github.com/samratashok/nishang)

## Working with Antak
* Can be found in the `/usr/share/nishang/Antak-WebShell`
* Like a PowerShell Console

```sh
$ ls /usr/share/nishang/Antak-WebShell

antak.aspx  Readme.md
```

#### Move a Copy for Modification
```sh
$ cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```

* Modify `line 14`, adding a user (green arrow) and password (orange arrow)

![[./Screenshots/antak-changes.png]]

![[./Screenshots/antak-creds-prompt.png]]

![[./Screenshots/antak-success.png]]
