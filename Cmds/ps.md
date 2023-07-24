

Lists processes system-wide. Also predefined alias for **Get-Process** cmdlet in powershell  
  
  
**-a** - Select all processes of all users  
**-u** - Select by effective user ID (EUID) or name. User-oriented format that provides detailed information about the processes  
**-x** - List the processes without a controlling terminal  
**-C** - Select by command name  
**-A** OR **-e** - Select all processes  
**-f** - Display full format listing  
**-o** - Specify individual output columns. Can be list. (**comm**, **pmem**, **pcpu**, etc)  
**--sort** _±column_ - Sort by column. _+_ Sorts ascending. _-_ Sorts by descending.  
**--forest** - Displays processes in a tree format for better child-parent relationship  
```bash
    PID TTY      TIME     CMD  
   2960 pts/0    00:00:00 bash  
   2983 pts/0    00:00:00  \_ ps
```
  
![[ps_sorting.png]]
  
EXAMPLES  
To see every process on the system using standard syntax:  
```bash
ps -e  
ps -ef  
ps -eF  
ps -ely
```

To see every process on the system using BSD syntax:  
```bash
ps ax  
ps axu
```

To print a process tree:  
```bash
ps -ejH  
ps axjf
```

To get info about threads:  
```bash
ps -eLf  
ps axms
```

To get security info:  
```bash
ps -eo euser,ruser,suser,fuser,f,comm,label  
ps axZ  
ps -eM
```

To see every process running as root (real & effective ID) in user format:  
```bash
ps -U root -u root u
```

To see every process with a user-defined format:  
```bash
s -eo pid,tid,class,rtprio,ni,pri,psr,pcpu,stat,wchan:14,comm  
ps axo stat,euid,ruid,tty,tpgid,sess,pgrp,ppid,pid,pcpu,comm  
ps -Ao pid,tt,user,fname,tmout,f,wchan
```

Print only the process IDs of syslogd:  
```bash
ps -C syslogd -o pid=
```

Print only the name of PID 42:  
```bash
ps -q 42 -o comm=
```