
Deep Packet Inspection (DPI) *aka* packet sniffing
- Method of examining the content of data packets as they pass by a checkpoint on the network


##### Scenario:
- Have compromised CONFLUENCE01, and can execute commands via HTTP requests.
- Blocked by a considerably restrictive network configuration when trying to pivot.
- DPI is terminating all outbound traffic except HTTP
- All inbound ports on CONFLUENCE01 are blocked except TCP/8090


- Can't rely on a normal reverse shell as it would not conform to the HTTP format and would be terminated at the network perimeter by the DPI solution.
- Can't create an SSH remote port forward for the same reason.
- Only traffic that will reach our Kali machine is HTTP
	- Can, for example, make requests with _Wget_ and _cURL_.

- FIREWALL/INSPECTOR device has replaced the previous simple firewall.
- MULTISERVER03 is blocked on the WAN interface.
- Have credentials for the PGDATABASE01 server
- Need to figure out how to SSH directly there through CONFLUENCE01.
- Need a tunnel into the internal network
- Must resemble an outgoing HTTP connection from CONFLUENCE01.

![](http-tunnel.png)

##### Execution:

