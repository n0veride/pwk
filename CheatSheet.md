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

### Removed from coursework:
[recon-ng](Tools.md#recon%28ng)
[pastebin](https://pastebin.com)
#### [theHarvester](Tools.md#theHarvester)

##### Search emails from a domain, limiting the results to 500, using DuckDuckGo:
```bash
theHarvester -d kali.org -l 500 -b duckduckgo
```
**-d** - Searches given domain  
**-b** - Utilizes given source (ie: google, baidu, twitter, etc) Needs API for some sources  
**-g** - Uses Google Dorks  
**-s** - Utilizes Shodan

[social-searcher](https://www.social-searcher.com)
[haveibeenpwned.com/PwnedWebsites](https://haveibeenpwned.com/PwnedWebsites)
[twofi](Tools.md#twofi)
[linkedin2username](Tools.md#linkedin2username)
[OSINT Framework](https://osintframework.com)
[maltego](https://www.maltego.com/maltego-community/)


# Enumeration
- check ftp  
- check rpcclient w/ null or guest login  
- check enum4linux  
- check smbclient/ cme smb  
- check ldapsearch  
- check dig & [dnsrecon ](Tools.md#dnsrecon) 
- [dirb](Tools.md#dirb) running w/ file exts (php, txt, html, asp)

## DNS:
### [dig](OS%20Commands.md#dig)
### [nslookup](OS%20Commands.md#nslookup)
### [Sublist3r](sublist3r.md)
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

dig axfr google.com

dig google.com ANY +nostat +nocmd +nocomments
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

##### Scan a domain, use a dictionary to brute force hostnames, do a standard scan, and save output as an xml:
```bash
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml
```

### [dnsenum](Tools.md#dnsenum)

##### Don't reverse lookup a domain, and output to an xml file:
```bash
dnsenum --noreverse -o mydomain.xml example.com
```


# Port Scanning:
#### [netcat](netcat.md)
TCP:
```bash
nc -nvv -w 1 -z 10.11.1.220 3388-3390
```
	-n : Skip DNS name resolution  
	-vv : Very verbose  
	-w : Timeout after 1 second  
	-z : Don't send any data  
UDP:
```bash
nc -nv -u -z -w 1 10.11.1.115 160-162
```

#### [nmap](nmap.md)
-sC - Default scripts

Save time and resources, scan multiple IPs for top ports:  
```bash
nmap -sT -A --top-ports=20 10.11.1.1-254 -oG top-port-sweep.txt
```
	**-sT** - Connect scan  
	**-A** - Aggressive scan: OS detection, traceroute, script scanning  
	**--top-ports** - Scans for given
	**-oG** - Output grep'able format
```bash
nmap <ip> -vv -n -Pn -p-  
(may need to add --max-scan-delay 0)  
  
sudo nmap 192.168.222.44 -p- -sV -vv --open --reason  
  
sudo nmap -A -sV -sC -sU <ip> --script=*enum -vv
```

##### FW/ IDS Evasion:
```bash
nmap -e NET_INTERFACE -Pn -S SPOOFED_IP 10.10.232.227
```
	*Note: Need to specify interface & disable Ping Scan:


#### [masscan](masscan.md)
```bash
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
```

### SMB:
#### [nbtscan](nbtscan.md)
```bash
sudo nbtscan -r 10.11.1.0/24
```

#### [nmap](nmap.md)
```bash
nmap -v -p 139,445 --script=smb* -oG smb.txt 10.11.1.1-245
```
[enum4linux](enum4linux.md)
[smbclient](smbclient.md)
[rpcclient](rpcclient.md)


### NFS:
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


### SMTP:
```bash
nc -nv <ip> 25

	VRFY root
```
\<vrfy.py\>


### SNMP:
	(UDP protocol)

```bash
sudo nmap -sU --open -p 161 <ip> -oG open-snmp.txt
```

#### [onesixtyone](onesixtyone.md)
```bash
#create list of all potential ips
for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
#scan for SNMP 'community' services
onesixtyone -c community -i ips
```

#### [snmpwalk](snmpwalk.md)
MIB Tree:
```bash
snmpwalk -c public -v1 -t 10 <ip>
```

##### Users:
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.4.1.77.1.2.25
```

##### Running Processes:
```bash
snmpwalk -c public -v1 <ip> 1.2.6.1.2.1.25.4.2.1.2
```

##### Open TCP Ports:
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.6.13.1.3
```

##### Installed Software:
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.6.3.1.2
```


## Vuln Scanning
```bash
sudo nmap --script vuln <ip>
```


## Web Apps

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