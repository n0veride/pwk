
Port scanner.  
  
Best to use _**sudo**_ when running **nmap** as many scanning options require access to raw sockets - which requires root privileges.  

```bash
nmap <ip> -vv -n -Pn -p-  
(may need to add --max-scan-delay 0)  
  
sudo nmap 192.168.222.44 -p- -sV -vv --open --reason  
  
  
sudo nmap -A -sV -sC -sU <ip> --script=*enum -vv
```
	enums  
  
###### Target & Port Specification:  
**-p** - Specify port or port range  
**-p-** - Scan all ports  
**--top-ports** <_x_> - Scans for given number _x_ of top ports (determined within _/usr/share/nmap/nmap-services_)  
**-iL** _\<filename\>_ - Scan targets from a file  
  
  
###### Scan Techniques:  
**-sS** - SYN scan/ “stealth” scan. Sends SYN packets to port w/o completing 3-way. Default scan when no other scan type is specified & with root privilege.  
Faster and more efficient. Also, as the handshake doesn't complete, info is not passed to the Application layer and will not appear on logs (however, may appear in Firewall logs)  
**-sT** - Connect scan. Completes 3-way handshake. Default scan w/o root privilege.  
Takes longer than SYN scan, but doesn't require elevated privileges as it uses Berkeley sockets API.  
**-sU** - UDP scan  
**-sA** - ACK scan - helpful w/ figuring out firewalls rule sets and config  
**-sW** - Window scan - Exactly like ACK scan, only examines TCP Window field of the RST packets returned  
**-sN**/ **-sF**/ **-sX** - TCP Null (doesn't set any bits/ TCP flag header is 0), FIN (just sets FIN bit), and XMAS scans (sets FIN, PSH, & URG flags -lighting the packet up like a christmas tree)  
**--scanflags** - Allows customization on which TCP flags are set  
  
  
###### Host Discovery: 
**-sL** - List scan. Lists targets to scan within block of IP addresses  
**-sn** - Ping scan. Disables port scan.  
**-Pn** - Skip host discovery - pinging host before scanning. (Windows by default blocks ICMP echo replys)  
**-PS** - SYN discovery on given port. Default: 80  
**-PA** - ACK discovery on given port. Default: 80  
**-PU** - UDP discovery on given port. Default: 80  
**-PR** - ARP discovery on a local network  
**-PE** - ICMP Echo Requests  
**-PM** - ICMP Address Mask Requests  
**-PP** - ICMP Timestamp Requests  
**-n** / **-R**: Never do DNS resolution/ Always resolve \[default: sometimes\]  
  
  
  
###### Service, Version, and OS Detection:  
**-A** - Aggressive scanning. Enables OS detection, version detection, script scanning, and traceroute  
**-O** - Enable OS detection using TCP/IP stack fingerprinting  
**-sV** - Probe banners to determine service/ version info  
**--version-intensity** <_x_/ _light_/ _all_> - Intenity level 0-9. Higher number increases possibility of correctness/ Enables light mode - faster, less correct/ Sets lvl to 9  
  
  
###### Timing and Performance:  
**-F** - Enable fast mode. Decreases number of scanned ports to 100 most common  
**-r** - Scans ports in consecutive order rather than random  
**-T**_#_ - Set speed of scan  
**0** - Paranoid. IDS evasion  
**1** - Sneaky. IDS evasion  
**2** - Polite. Slows scan to use less bandwidth and less target machine resources  
**3** - Normal. Default speed  
**4** - Aggressive. Assumes you're on a fast and reliable network  
**5** - Insane. Assumes an extraordinarily fast network  
  
  
###### Firewall/ IDS Evasion and Spoofing:  
**-D** _\<decoy-ip-list\>_- Send scans from spoofed IPs  
**-f** - Used to fragment the packets (i.e. split them into smaller pieces) making it less likely that the packets will be detected by a firewall or IDS  
**-g** _\<port\>_ - Use given source port number  
**-S** - Designate spoofed-IP

```bash
nmap -e NET_INTERFACE -Pn -S SPOOFED_IP 10.10.232.227
```
	*Note: Need to specify interface & disable Ping Scan:

**--spoof-mac** - Designate spoofed-mac address  
**-sI** - Idle/ zombie scan. Requires idle system on network and pushes scans through its IP.  
**--badsum** - Generate in invalid checksum for packets. Can be used to determine the presence of a firewall/IDS.  
**--data-length** _\<length\>_ - Appends random data to sent packets  
**--mtu** _\<number\>_ - Similar to **-f**, but allows specifying size of packet. This _must_ be a multiple of 8.  
**--scan-delay** _\<time\>_ - Adds a delay between packets sent. Useful if the network is unstable and for evading any time-based firewall/IDS triggers which may be in place.  
  
  
###### NSE Scripts:  
**-sC** - Default scripts. Considered useful for discovery and safe  
**--script=**_<script/ */ ,script>_ - Scan with specified script/s. Can use single script. Can use wildcard for all scripts w/ of a kind (Ex: http*), Can scan with multiple scripts comma separated  
**--script-args** - Specifies arguments of previously specified **--script=**_script_  
  
  
###### Output:  
**-oG** - Output results in **grep**-able format  
**-oG -** - Grepable output to the screen. Ex:
```bash
nmap -p80 -sV -oG - --open 192.168.1.1/24 | grep open
```
	Scan for web servers and grep to show which IPs are running them  
**-oX** - Outputs to XML  
**-oA** - Output all formats  
**-oN** - Requests normal output be given to the file name  
**--apend-output** - Appends a scan to a previous scan file  
**-v**/ **-vv** - Increase verbosity level (Displays results as they come)  
**-d**/ **-dd** - Increase debugging level  
**--open** - Only return matches with open ports  
  
  
###### Etc:  
**--dns-servers** - Specify custom DNS servers  
**--system-dns** - Use OS's DNS resolver  
**--traceroute** - Trace hop path to each host  

  
###### States:  
  
1. **Open**: indicates that a service is listening on the specified port.  
2. **Closed**: indicates that no service is listening on the specified port, although the port is accessible.  
	By accessible, we mean that it is reachable and is not blocked by a firewall or other security appliances/programs.  
3. **Filtered**: means that Nmap cannot determine if the port is open or closed because the port is not accessible.  
	This state is usually due to a firewall preventing Nmap from reaching that port.  
	Nmap’s packets may be blocked from reaching the port; alternatively, the responses are blocked from reaching Nmap’s host.  
4. **Unfiltered**: means that Nmap cannot determine if the port is open or closed, although the port is accessible.  
	This state is encountered when using an ACK scan **-sA**.  
5. **Open|Filtered**: This means that Nmap cannot determine whether the port is open or filtered.  
6. **Closed|Filtered**: This means that Nmap cannot decide whether a port is closed or filtered.