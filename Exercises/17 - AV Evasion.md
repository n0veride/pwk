
# 17.3.5.5
In this exercise, you'll be facing off against **COMODO** antivirus engine running on VM #1.  
Use another popular 32-bit application, like Putty, to replicate the steps learned so far in order to inject malicious code in the binary with Shellter.  
The victim machine runs an anonymous FTP server with open read/write permissions. Every few seconds, the victim user will double-click on any existing **.exe** Windows PE file(s) in the FTP root directory.  
If the antivirus flags the script as malicious, the script will be quarantined and then deleted. Otherwise, the script will execute and, hopefully, grant you a reverse shell.  
**NOTE:** set the FTP session as _active_ and enable _binary_ encoding while transferring the file.  
  
  
Using WinRAR.exe from the chapter.  
  
Use default user: anonymous. No pw.  
  
**passive..... Prevents entering Extended Passive Mode when attempting to upload binary

```bash
ftp <vic_ip>  
	Connected to 192.168.224.53.  
	220 Microsoft FTP Service  
	Name (192.168.224.53:kali): Anonymous  
	331 Anonymous access allowed, send identity (e-mail name) as password.  
	Password:   
	230 User logged in.  
	Remote system type is Windows_NT.  
ftp> passive  
	Passive mode: off; fallback to active mode: off.  
ftp> bin  
	200 Type set to I.  
ftp> put winrar-x32-611.exe   
	local: winrar-x32-611.exe remote: winrar-x32-611.exe  
	200 EPRT command successful.  
	150 Opening BINARY mode data connection.
	100% |*****************************************************|  3140 KiB  579.11 KiB/s    00:00 ETA  
	226 Transfer complete.  
	3215872 bytes sent in 00:05 (569.71 KiB/s)
```

In [**Meterpreter**](Meterpreter.md) session:
```bash
cat C:\\Users\\Administrator\\Desktop\\flag.txt
```


# 17.3.5.6
Similar to the previous exercise, you'll be facing off against **COMODO** antivirus engine v12.2.2.8012 on VM #2.  
  
Although the PowerShell AV bypass we covered in this module is substantial, it has an inherent limitation:  
The malicious script cannot be "double-clicked" by the user for an immediate execution. Instead, it would open in **notepad.exe** or another default text editor.  
  
The tradecraft of manually weaponizing PowerShell scripts is beyond the scope of this module, but we can rely on another open-source framework to help us automate this process.  
Research how to install and use the [Veil](https://github.com/Veil-Framework/Veil) framework to help you with this challenge.  
The victim machine runs an anonymous FTP server with open read/write permissions.  
Every few seconds, the victim user will double-clck on any existing **.bat** Windows batchscript file(s) in the FTP root directory.  
If the antivirus flags the script as malicious, the script will be quarantined and then deleted. Otherwise, the script will execute and, hopefully, grant you a reverse shell

[**Veil**](Veil.md):
![[veil.png]]

list:
![[veil1.png]]
![[veil2.png]]
![[veil3.png]]

Payload is saved to:
```bash
/var/lib/veil/output/source/payload.bat
```