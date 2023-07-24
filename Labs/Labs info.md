```bash
sudo nmap -iL ips -Pn -sV -sC -v --open -p- | tee tcp-scan  
sudo nmap -iL ips -Pn -sV -sC -sU -v --open -p- | tee udp-scan
```

Various simulated clients will perform their task(s) at different time intervals.  
Most common is 5 min.  
  
Some targets can't be exploited w/o first gathering specific info on another lab machine.  
  
Some can only be exploited through a pivot.  
  
Machine dependencies will not be provided - need to be discovered on own  
  
Certain vuln machines will contain a **network-secret.txt** file w/ an MD5 hash in it.  
This hash will unlock addt networks in the control panel.  
  
IT, Dev, & Admin networks aren't directly routable from the public student network.  
May need to:  
Exploit machines NAT'd behind firewalls  
Leverage dual-homed hosts  
Client-side exploits  
  
Public student network is routable from all other networks.  
  
IPs aren't significant  
May not be able to fully compromise a certain network w/o first moving into another  
  
Firewalls et. al. aren't directly exploitable.  
In scope, but not intentionally created to exploit.  
DOS/ DDOS or bruteforcing is discouraged as everything connected will render them inaccessible to people.  
  
Excessive amount of time cracking root/ admin pws isn't required.  
Wordlists used in other modules: /usr/share/wordlists/rockyou.txt, cewl, OSINT, etc should be sufficient.

![file:///tmp/.B6HBZ1/1.png](file:///tmp/.B6HBZ1/1.png)