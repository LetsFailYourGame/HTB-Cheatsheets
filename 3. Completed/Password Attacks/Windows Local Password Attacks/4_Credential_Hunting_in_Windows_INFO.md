* `Credential Hunting` is the process of performing detailed searches across the file system and through various applications to discover credentials

## Search Centric
* A user may have documented their passwords somewhere on the system
* There may even be default credentials that could be found in various files
* It would be wise to base our search for credentials on what we know about how the target system is being used

```
What might an IT admin be doing on a day-to-day basis & which of those tasks may require credentials?
```

#### Key Terms to Search

![](Screenshot_2022-11-12_164030.png)

## Search Tools
* With access to the GUI, it is worth attempting to use `Windows Search` to find files on the target using some keywords mentioned above
* We can also take advantage of third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store
* We can use our RDP client to copy the file over to the target from our attack host
* Using `xfreerdp` all we must do is copy and paste into the RDP session we have established

#### Running Lazagne All
* We can include the option `-vv` to study what it is doing in the background

```powershell
C:\Users\bob\Desktop> start lazagne.exe all
```

```powershell
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```

#### Using findstr
* Use [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr) to search from patterns across many types of files

```powershell
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Additional Considerations
-   Passwords in Group Policy in the SYSVOL share
-   Passwords in scripts in the SYSVOL share
-   Password in scripts on IT shares
-   Passwords in web.config files on dev machines and IT shares
-   unattend.xml
-   Passwords in the AD user or computer description fields
-   KeePass databases --> pull hash, crack and get loads of access.
-   Found on user systems and shares
-   Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)