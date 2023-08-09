

[DNS Enumeration](7.1%20-%20DNS%20Enum.md): [host](Cmdline%20Tools.md#host), forward/ reverse lookup brute force, [dnsrecon](dnsrecon.md), [dnsenum](dnsenum.md), [dig](Cmdline%20Tools.md#dig) .... adding [nslookup](nslookup.md)  
  
[Port Scanning](7.2%20-%20Port%20Scanning.md)  
  
[Masscan](masscan.md)  
  
[SMB Enumeration](7.3%20-%20SMB%20Enum.html.md)  
  
[NFS Enumeration](7.4%20-%20NFS%20Enum.html.md)

[SMTP Enumeration](7.5%20-%20SMTP%20Enum.md)

[SNMP Enumeration](7.6%20-%20SNMP%20Enum.md)  
  
  
[netdiscover](netdiscover.md) - Discover hosts  
  
  
```bash
nmap <ip> -vv -n -Pn -p-  
(may need to add --max-scan-delay 0)  
  
sudo nmap 192.168.222.44 -p- -sV -vv --open --reason  
  
  
sudo nmap -A -sV -sC -sU <ip> --script=*enum -vv
```
- check ftp  
- check rpcclient w/ null or guest login  
- check enum4linux  
- check smbclient/ cme smb  
- check ldapsearch  
- check dig & dnsrecon  
- dirb running w/ file exts (php, txt, html, asp)