# OSINT

### [whois](Tools.md#whois)

##### Forward Lookup:
```bash
whois megacorpone.com -h 192.168.50.251
```

##### Reverse Lookup:
```bash
whois 38.100.193.70 -h 192.168.50.251
```

### [Google Dorks](Tools.md#Google%20Dorks)  
##### Limit to single domain:
```bash
site:megacorpone.com
```

##### Search for subdomains while ignoring *www*.  
```bash
site:*.megacorpone.com -site:www.megacorpone.com
```

##### Remove html pages from a search:
```bash
site:megacorpone.com -filetype:html
```

##### Search for filetypes:
```bash
site:megacorpone.com filetype:php
site:megacorpone.com ext:jsp
site:megacorpone.com ext:cfm
site:megacorpone.com ext:pl
```

##### Pages with given words or strings in them:
```bash
intitle:“index of” “parent directory”
```
	Shows results w/ “index of” in the title and “parent directory” somewhere on the page.  

### [Netcraft](Tools.md#Netcraft)
### [GitLeaks](Tools.md#GitLeaks)
### [GitRob](Tools.md#GitRob])
### [Shodan.io](Tools.md#Shodan%29io)

##### Filters:
```bash
hostname:megacorpone.com
port:"22"
```

[Security Headers](Tools.md#Security%20Headers)
[SSL Server Test](Tools.md#SSL%20Labs)


### [recon-ng](Tools.md#recon%28ng) -removed

##### Create workspace:
```bash
workspaces create wksp_name
```

##### Return to/ work in workspace:
```bash
recon-ng -w wksp_name
```

##### Display list of all modules:
```bash
marketplace search
```

##### Display list of all ssl modules:
```bash
marketplace search ssl
```

##### Find info on a specific module:
```bash
marketplace info ssltools
```

##### Install and load module:
```bash
marketplace install hackertarget
marketplace load hackertarget
```

##### Show options and set source:
```bash
show options
options set SOURCE site.com
```

##### View inputs:
```bash
input
```

##### Execute:
```bash
run
```

### [pastebin](https://pastebin.com) -removed
### [theHarvester](Tools.md#theHarvester) -removed

##### Search emails from a domain, limiting the results to 500, using DuckDuckGo:
```bash
theHarvester -d kali.org -l 500 -b duckduckgo
```
	-d - Searches given domain  
	-b - Utilizes given source (ie: google, baidu, twitter, etc) Needs API for some sources  
	-g - Uses Google Dorks  
	-s - Utilizes Shodan

### [social-searcher](https://www.social-searcher.com) -removed

### [haveibeenpwned.com/PwnedWebsites](https://haveibeenpwned.com/PwnedWebsites) -removed

### [twofi](Tools.md#twofi) -removed

### [linkedin2username](Tools.md#linkedin2username) -removed

### [OSINT Framework](https://osintframework.com) -removed

### [maltego](https://www.maltego.com/maltego-community/) -removed


# Enumeration
- check ftp  
- check rpcclient w/ null or guest login  
- check enum4linux  
- check smbclient/ cme smb  
- check ldapsearch  
- check [dig](Tools.md#dig) & [dnsrecon ](Tools.md#dnsrecon) 
- [dirb](Tools.md#dirb) running w/ file exts (php, txt, html, asp)

## DNS:

### [host](Tools.md#host)
##### NameServers:
```bash
host -t ns google.com | cut -d " " -f 4
```

##### Forward Lookup Brute Force:
```bash
for ip in $(cat /usr/share/seclists/); do host $ip.megacorpone.com; done
```

##### Reverse Lookup Brute Force:
```bash
for ip in $(seq 200 225); do host 51.222.169.$ip; done | grep megacorpone | grep -v "not found"
```

##### Zone Transfers:
```bash
host -l megacorpone.com ns1.megacorpone.com
```

##### \<axfr.sh & axfr.py\>:
```bash
#!/bin/bash
#Zone Transfer bash script
if [ -z "$1" ]; then
	echo "[*] Simple Zone transfer script"
	exho "[*] Usage   :  $0 <domain name>"
	exit 0
fi

for server in $(host -t ns $1 | cut -d " " -f 4); do
	host -l $1 $server | grep "has address"
done
```


### [dnsrecon](Tools.md#dnsrecon)

##### Perform a standard scan:
```bash
dnsrecon -d megacorpone.com -t std
```

##### Perform a brute force attack on a domain using a file with potential subdomain strings:
```bash
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
```

##### Perform a standard scan brute force attack on a domain using a hostname dictionary and save output as an xml:
```bash
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml
```

### [dnsenum](Tools.md#dnsenum)

##### Run a simple DNS enumeration scan:
```bash
dnsenum megacorpone.com
```

##### Don't reverse lookup a domain, and output to an xml file:
```bash
dnsenum --noreverse -o mydomain.xml example.com
```


### [nslookup](Tools.md#nslookup) - Windows

##### Simple A record query:
```powershell
nslookup mail.megacorptwo.com
```

##### Query a given DNS server (192.168.50.151) about a TXT record that belongs to a specific host (info.megacorptwo.com):
```powershell
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

##### Enable debug mode, grabbing IPv4 & IPv6, combining record types, using recursive lookup on 1.1.1.1 DNS server, w/o searching the domain
```powershell
nslookup -debug -type=A+AAAA -nosearch -recurse mydomain.com 1.1.1.1
```


### [dig](Tools.md#dig) -removed

##### Search A records:
```bash
dig megacorpone.com
```

##### Search TXT records:
```bash
dig TXT megacorpone.com
```

##### Search all records:
```bash
dig ANY megacorpone.com +noall +answer
```

##### Zone Transfers:
```bash
dig axfr google.com

dig google.com ANY +nostat +nocmd +nocomments
```

### [Sublist3r](Tools.md#sublist3r) -removed

##### Enumerate subdomains of a specific domain:
```python
python sublist3r.py -d example.com
```

##### Enumerate subdomains and show only those with open ports 80 & 443
```python
python sublist3r.py -d example.com -p 80,443
```

##### Enable brute force module
```python
python sublist3r.py -b -d example.com
```

##### Use specific search engines
```python
python sublist3r.py -e google,yahoo,virustotal -d example.com
```



## Port Scanning:
### [netcat](Tools.md#netcat)

##### TCP scanning:  
```bash
nc -nvv -w 1 -z 10.11.1.220 3388-3390
```

##### UDP scanning:  
```bash
nc -nv -u -z -w 1 10.11.1.115 160-162
```


### [nmap](Tools.md#nmap)

##### SYN scan:
```bash
sudo nmap -sS 192.168.50.149
```

##### TCP Connect scan:
```bash
nmap -sT 192.168.50.149
```

##### UDP scan:
```bash
sudo nmap -sU 192.168.50.149
```

##### SYN & UDP scan:
```bash
sudo nmap -sU -sS 192.168.50.149
```

##### Network Sweep exported to grep'able format & view only hosts reported as "Up":
```bash
nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt

grep Up ping-sweep.txt | cut -d " " -f 2
```

##### Scan multiple IPs for top ports:
```bash
nmap -sT -A --top-ports=20 192.168.50.-253 -oG top-port-sweep.txt
```
	**-sT** - Connect scan  
	**-A** - Aggressive scan: OS detection, traceroute, script scanning  
	**--top-ports** - Scans for given number (20) of top ports (determined within _/usr/share/nmap/nmap-services_)
	**-oG** - Output grep'able format

##### OS Fingerprinting:
```bash
sudo nmap -O 192.168.50.14 --osscan-guess
```

##### Banner Grabbing:
```bash
nmap -sT -A 192.168.50.14
```

##### NSE:
```bash
nmap --script http-headers 192.168.50.6
nmap --script-help http-headers
```

##### NSE script search:
```bash
grep <script keyword> /usr/share/nmap/scripts/script.db
```

##### NSE - Aggressive, Service version, UDP scan using all default enumeration scripts
```bash
sudo nmap -A -sV -sC -sU 192.168.50.14 --script=*enum -vv
```


##### Scan all ports, skip host discovery - Removed
```bash
nmap 192.168.50.14 -vv -n -Pn -p-
	(may need to add --max-scan-delay=0)
```

```bash
sudo nmap 192.168.50.14 -p- -sV -vv --open --reason  
```

##### FW/ IDS Evasion: - Removed
```bash
nmap -e NET_INTERFACE -Pn -S SPOOFED_IP 10.10.232.227
```
	*Note: Need to specify interface & disable Ping Scan:


### PowerShell port scanning

##### Single port scan:
```powershell
Test-NetConnection -Port 445 192.168.50.151
```
##### Multiple port scan (takes forever):
```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

### [masscan](Tools.md#masscan) - removed

```bash
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
```


## SMB:

### [nmap](Tools.md#nmap)

##### Enumerate SMB & NetBIOS using all NSE SMB scripts:
```bash
nmap -v -p 139,445 --script=smb* -oG smb.txt 10.11.1.1-245
```

##### OS Discovery:
```bash
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
```

##### SMB RCE Vuln:
```bash
nmap -v -p 139,445 --script smb-vuln-ms08-067 --script-args=unsafe=1 192.168.50.152
```
	w/ Script parameter set to **unsafe=1**, the scripts that run are almost/ totally guaranteed to crash a vulnerable system.
	  Use extreme caution when enabling this arg.

### [nbtscan](Tools.md#nbtscan)
```bash
# -r specifies the originating UDP port as 137
sudo nbtscan -r 10.11.1.0/24
```

### net view
```powershell
net view \\dc01 /all
```


### [enum4linux](Tools.md#enum4linux)

##### Get userlist and OS info:
```bash
enum4linux -U -o 192.168.1.200
```


### [smbclient](Tools.md#smbclient)

##### List shares:
```bash
smbclient -L //IP
smbclient -L <ip>
smbclient -L //IP -I "DOMAINNAME\User"
```

##### Connect:
```bash
smbclient \\x.x.x.x\\share
smbclient -U "DOMAINNAME\User" //<ip>/IPC$ password
```

### [rpcclient](Tools.mdrpcclient)

##### Anonymous Connection:
```bash
rpcclient 10.10.0.1 -U "" -N 
```

##### Connect w/ User sec504:
```bash
rpcclient 10.10.0.1 -U sec504
```

Once Connected:
##### Get Server info:
```bash
srvinfo
```

##### Enumerate through info:
```bash
enumdomusers
enumdomgroups
enumalsgroups builtin
```

##### Get domain pw policy:
```bash
getdompwinfo
```


## SMTP:

##### nmap enumeration:
```bash
sudo nmap -p 25 --script=smtp-enum* <target DOMAIN/ip>
```

##### Connect via NC:
```bash
nc -nv <ip> 25
```

##### Connect via Telnet:
```powershell
telnet <ip> 25
```

##### Start session and verify user:
```smtp
HELO <domain name OR ip>
VRFY <user>
EXPN <mailing list>
QUIT
```


## SNMP:
	(UDP protocol)

##### nmap enumeration:
```bash
sudo nmap -sU --open -p 161 <ip> -oG open-snmp.txt
```

### [onesixtyone](Tools.md#onesixtyone)

##### Create list of all potential ips:
```bash
for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
```

##### Create list of services:
```bash
echo public > community
echo private >> community
echo manager >> community
```

##### Brute Force IPs for 'community' services:
```bash
onesixtyone -c community -i ips
```

##### Results will look like:
```bash
Scanning 254 hosts, 3 communities
192.168.247.151 [public] Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
```
	Gives open host: 192.168.247.151 w/ public community

### [snmpwalk](Tools.md#snmpwalk)
##### MIB Tree Probe and Query Public Values:
```bash
snmpwalk -c public -v1 -t 10 <ip>
```
	Good for getting target email addresses

##### Users:
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.4.1.77.1.2.25
```

##### Running Processes:
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.4.2.1.2
```

##### Open TCP Ports:
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.6.13.1.3
```

##### Installed Software:
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.6.3.1.2
```


### [snmpcheck](Tools.md#snmpchec k)

couldn't get to work in lab

## NFS: - Removed
```bash
nmap -sV -p 111 --script=nfs* <ip>
nmap -sV -p 111 --script=rpcinfo <ip>
```

```bash
mkdir home
sudo mount -o nolock <ip>:<nfs mount point> ~/home/
```

(Change UUID):
```bash
sudo sed -i -e 's/old_UUID/new_UUID/g' /etc/passwd
```



# Vuln Scanning
```bash
sudo nmap --script vuln <ip>
```


# Web Apps

### Enum
Inspect
- URLs
- Page Content
- Response Headers
- Sitemaps (robots.txt, sitemap.xml, etc)
- [Default admin consoles & logins](8.x%20-%20Admin%20Consoles.md)

#### [dirb](dirb.md)
```bash
dirb http://<domain> -r -z 10
```

#### [nikto](nikto.md)
```bash
nikto -host=http://<domain> -maxtime=30s
```


### Admin Consoles

#### [BurpSuite](burpsuite.md)
	Intruderd







Linux PrivEsc:

##### perl
```bash
sudo /usr/bin/perl -e 'exec("/bin/bash")'
```