![](PivotingandTunnelingVisualized.gif)

* If we want to access a target which is not directly reachable from our attack host we might have to use a pivot host that we have already compromised
* One of the most important things to do when landing on a host for the first time is to check our `privilege level`, `network connections`, and potential `VPN or other remote access software`
* If a host has more than one network adapter, we can likely use it to move to a different network segment
* Pivoting is essentially the idea of `moving to other networks through a compromised host to find more targets on different network segments`
* There are many different terms used to describe a compromised host that we can use to `pivot` to a previously unreachable network segment
* Some of the most common names are:
	* `Pivot Host`
	- `Proxy`
	- `Foothold`
	- `Beach Head system`
	- `Jump Host`
- Pivoting's primary use is to defeat segmentation (both physically and virtually) to access an isolated network
- `Tunneling` is a subset of pivoting
- Tunneling encapsulates network traffic into another protocol and routes traffic through it

## Lateral Movement, Pivoting, and Tunneling Compared
* [Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
	* Can be described as a technique used to further our access to additional `hosts`, `applications`, and `services` within a network environment
	* Can also help us gain access to specific domain resources we may need to elevate our privileges
	* Often enables privilege escalation across hosts
	* Practical example
		* During an assessment, we gained initial access to the target environment and were able to gain control of the local administrator account. We performed a network scan and found three more Windows hosts in the network. We attempted to use the same local administrator credentials, and one of those devices shared the same administrator account. We used the credentials to move laterally to that other device, enabling us to compromise the domain further`
* Pivoting
	* Utilizing multiple hosts to cross `network` boundaries you would not usually have access to
	* More of a targeted objective
	* The goal here is to allow us to move deeper into a network by compromising targeted hosts or infrastructure
	* Practical example
		* During one tricky engagement, the target had their network physically and logically separated. This separation made it difficult for us to move around and complete our objectives. We had to search the network and compromise a host that turned out to be the engineering workstation used to maintain and monitor equipment in the operational environment, submit reports, and perform other administrative duties in the enterprise environment. That host turned out to be dual-homed (having more than one physical NIC connected to different networks). Without it having access to both enterprise and operational networks, we would not have been able to pivot as we needed to complete our assessment.
* Tunneling
	* The key here is obfuscation of our actions to avoid detection for as long as possible
	* We utilize protocols with enhanced security measures such as HTTPS over TLS or SSH over other transport protocols
	* These types of actions also enable tactics like the exfiltration of data out of a target network or the delivery of more payloads and instructions into the network
	* Practical example
		* One way we used Tunneling was to craft our traffic to hide in HTTP and HTTPS. This is a common way we maintained Command and Control (C2) of the hosts we had compromised within a network. We masked our instructions inside GET and POST requests that appeared as normal traffic and, to the untrained eye, would look like a web request or response to any old website. If the packet were formed properly, it would be forwarded to our Control server. If it were not, it would be redirected to another website, potentially throwing off the defender checking it out.