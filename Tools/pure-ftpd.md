

Quick & easy FTP server  
  
offsec / lab  
  
Setup:  
```bash
sudo apt update && sudo apt install pure-ftpd

cat > setup-ftp.sh
#!/bin/bash

sudo groupadd ftpgroup  
sudo useradd -g ftpgroup -d /dev/null -s /etc ftpuser  
sudo pure-pw useradd offsec -u ftpuser -d /ftphome  
sudo pure-pw mkdb  
cd /etc/pure-ftpd/auth/  
sudo ln -s ../conf/PureDB 60pdb  
sudo mkdir -p /ftphome  
sudo chown -R ftpuser:ftpgroup /ftphome/  
sudo systemctl restart pure-ftpd.service
#Ctrl + D

chmod +x setup-ftp.sh
./setup-ftp.sh
systemctl status pure-ftpd
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