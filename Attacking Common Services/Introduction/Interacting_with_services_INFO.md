## File Share Services
* Provides, mediates, and monitors the transfer of computer files
* Most companies now also have third-party cloud services such as Dropbox, Google Drive, OneDrive, SharePoint, or other forms of file storage such as AWS S3, Azure Blob Storage, or Google Cloud Storage instead of SMB, NFS, FTP, TFTP or SFTP

## Server Message Block (SMB)
* Commonly used in Windows networks
	* Share folders
* Interact using a GUI or CLI as well as other tools

#### Windows
* On Windows, we can press `WIN + R` and then connect to an SMB share via `\\192.168.220.129\Finance\`, `\\<ip>\<share>`
* If anonymous login is allowed, or we have access to a user who has privileges we can view that shared folder

#### Windows CMD - DIR
* We can also use the Command Shell (`CMD`) and `PowerShell`

```powershell
C:\htb> dir \\192.168.220.129\Finance\

Volume in drive \\192.168.220.129\Finance has no label.
Volume Serial Number is ABCD-EFAA

Directory of \\192.168.220.129\Finance

02/23/2022  11:35 AM    <DIR>          Contracts
               0 File(s)          4,096 bytes
               1 Dir(s)  15,207,469,056 bytes free
```

#### Windows CMD - Net Use
* Connects a computer to or disconnects a computer from a shared resource or displays information about computer connections
* Specify drive letter e.g `n`

```powershell
C:\htb> net use n: \\192.168.220.129\Finance

The command completed successfully.
```

```powershell
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123

The command completed successfully.
```

* We can execute Windows commands as if this shared folder is on our local computer

```powershell
C:\htb> dir n: /a-d /s /b | find /c ":\"

29302
```

* `dir` - Application
* `n:` - Directory or drive to search 
* `/a-d` - `/a` is the attribute and `-d` means not directories
* `/s` - Displays files in a specified directory and all subdirectories
* `/b` - Bare format (no heading information or summary)
* The following command `| find /c ":\\"` process the output of `dir n: /a-d /s /b` to count how many files exits in the directory and subdirectories

```powershell
C:\htb>dir n:\*cred* /s /b
n:\Contracts\private\credentials.txt

C:\htb>dir n:\*secret* /s /b
n:\Contracts\private\secret.txt
```

```powershell
c:\htb>findstr /s /i cred n:\*.*
n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!
```

#### Windows PowerShell
```powershell
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\

    Directory: \\192.168.220.129\Finance

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/23/2022   3:27 PM                Contracts
```

* Instead of `net use`, we can use `New-PSDrive` in PowerShell

```powershell
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

#### Windows PowerShell - PSCredential Object
```powershell
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

#### Windows PowerShell - GCI
* We can use the command `Get-ChildItem` or the short variant `gci` instead of the command `dir`

```powershell
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```

* Use `-Include` to find specific items from the directory specified by the Path parameter

```powershell
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

    Directory: N:\Contracts\private

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2022   4:36 PM             25 credentials.txt
```

* The `Select-String` cmdlet uses regular expression matching to search for text patterns in input strings and files
* Similar to grep

```powershell
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List

N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```

#### Linux - Mount
```sh
sudo mkdir /mnt/Finance
sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

```sh
mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

#### CredentialFile
```txt
username=plaintext
password=Password123
domain=.
```

**Note**: We need to install `cifs-utils` to connect to an SMB share folder. To install it we can execute from the command line `sudo apt install cifs-utils`.

#### Linux - Find
```sh
find /mnt/Finance/ -name *cred*

/mnt/Finance/Contracts/private/credentials.txt
```

```sh
grep -rn /mnt/Finance/ -ie cred

/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```

## MSSQL
```sh
sqsh -S 10.129.20.13 -U username -P Password123
```

```powershell
C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
```

## MySQL
```sh
mysql -u username -pPassword123 -h 10.129.20.13
```

```powershell
C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13
```

#### GUI Application
```sh
# Install
sudo dpkg -i dbeaver-<version>.deb

# Run 
dbeaver &
```

#### Tools to Interact with Common Services
![[../../Screenshots/Screenshot_2022-11-07_212415.png]]
