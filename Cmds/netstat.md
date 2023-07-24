
Network Statistics  
  

Mostly obsolete. Useful in Windows  
  
Replacement for netstat is **ss**  
Replacement for **netstat -r** is **ip route**.  
Replacement for **netstat -i** is **ip -s link**.  
Replacement for **netstat -g** is **ip maddr**  
  

**<#>** - Automatically refresh every <#> seconds
**-a** - Display all active (listening & non-listening) TCP connections
**-b** - Display .exe (or .dll) name associated w/ listening process (req admin/ root)
**-c** - Continuous monitoring: Print info from route cache.
**-g** - Display multicast group membership info
**-i** - Display table of all network interfaces
**-l** - Display only listening sockets
**-m** - Display list of masqueraded conns
**-n** - Display address & port number in numerical form (Turns off name resolution)
**-o** - Display owner PID of each conn  
**-p** - Display process PID & name the conn belongs to
**-r** - Display kernel routing tables
**-s** - Display statistics for each protocol
**-t** - Display TCP only
**-u** - Display UDP only
**-w** - Display raw information