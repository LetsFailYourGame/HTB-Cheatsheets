* One of the most common authentication method is [Pluggable Authentication Modules](http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html) (`PAM`)
* The modules used for this are called `pam_unix.so` or `pam_unix2.so` and are located in `/usr/lib/x86_x64-linux-gnu/security/` in Debian based distributions
* These modules manage user information, authentication, sessions, current passwords, and old passwords
* If we for example want to change the password of our account on the Linux system with `passwd`, PAM is called, which takes the appropriate precautions and stores and handles the information accordingly
* The `pam_unix.so` standard module for management uses standardized API calls from the system libraries and files to update the account information.
* The standard files that are read, managed, and updated are `/etc/passwd` and `/etc/shadow`
* PAM also has many other service modules, such as LDAP, mount, or Kerberos

## Passwd File
* Contains information about every existing user on the system and can be read by all users and services
* Each entry in the `/etc/passwd` file identifies a user on the system
* Each entry has seven fields containing a form of a database with information about the particular user, where a colon (`:`) separates the information

#### Passwd Format

| majix      | x             | 1000 | 1000 | majix,,,             | /home/majix    | /bin/bash |
| ---------- | ------------- | ---- | ---- | -------------------- | -------------- | --------- |
| Login name | Password info | UID  | GUID | Full name / comments | Home directory | Shell          |

* Interesting field : Password info
* On old systems, we may find a hash of the encrypted password
* Usually the value `x` → hash is stored in `/etc/shadow`
* Possible that the `/etc/passwd` is writable by accident
* Allows us to clear this field for the user `root` so that the password field is empty

#### Editing /etc/passwd - Before

```sh
root:x:0:0:root:/root:/bin/bash

root::0:0:root:/root:/bin/bash
```

```sh
head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash

su

[root@parrot]─[/home/root]#
```

## Shadow File
* Only responsible for passwords and their management
* Contains all the password information for the created users
* If there is no entry in the `/etc/shadow` file for a user in `/etc/passwd`, the user is considered invalid
* The `/etc/shadow` file is also only readable by users who have administrator rights
* If the password field contains a character, such as `!` or `*`, the user cannot log in with a Unix password
	* Other authentication methods for logging in, such as Kerberos or key-based authentication, can still be used
* Same case applies if the `encrypted password` field is empty
	* Means that no password is required for the login
	* Can lead to specific programs denying access to functions
* Hash format - `$<type>$<salt>$<hashed>`
	* `$1$` – MD5
	- `$2a$` – Blowfish
	- `$2y$` – Eksblowfish
	- `$5$` – SHA-256
	- `$6$` – SHA-512 (Default)

| majix    | \$6\$wBRzy\$...SNIP...x9cDWUxW1 | 18937          | 0           | 99999       | 7              |                 |                 |
| -------- | ------------------------------- | -------------- | ----------- | ----------- | -------------- | --------------- | --------------- |
| Username | Encrypted password              | Last PW change | Min. PW age | Max. PW age | Warning perios | Inactive period | Expiration date | Unused

```sh
sudo cat /etc/shadow

root:*:18747:0:99999:7:::
sys:!:18747:0:99999:7:::
...SNIP...
cry0l1t3:$6$wBRzy$...SNIP...x9cDWUxW1:18937:0:99999:7:::
```

## Opasswd
* The PAM library (`pam_unix.so`) can prevent reusing old passwords
* The file where old passwords are stored is the `/etc/security/opasswd`
* Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually

```sh
sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

## Cracking Linux Credentials
* Once we have collected some hashes, we can try to crack them in different ways to get the passwords in clear text

#### Unshadow

```sh
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak 
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

#### Hashcat - Cracking Unshadowed Hashes

```sh
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

#### Hashcat - Cracking MD5 Hashes

```sh
cat md5-hashes.list

qNDkF0zJ3v8ylCOrKB0kt0
E9uMSmiQeRh4pAAgzuvkq1
```

```sh
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```