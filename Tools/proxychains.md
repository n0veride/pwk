

Proxy tool.  
Hooks network-related libc functionsin dynamically linked programs via a preloaded DLL and redirects theconnections through SOCKS4a/5 or HTTP proxies.  
  
  
Config file: **/etc/proxychains4.conf**  
  
Need to edit and add whichever proxy we're using & then pass each command through **proxychains**  
  
  
Ex:  
Dynamic SSH tunnel:
```bash
sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128  
  
vim /etc/proxychains4.conf  
...  
[ProxyList]  
# add proxy here ...  
# meanwile  
# defaults set to "tor"  
socks4  127.0.0.1 8080  
  
sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110  
Starting Nmap 7.60 ( https://nmap.org ) at 2019-04-19 18:18 EEST  
|S-chain|-<>-127.0.0.1:8080-<><>-192.168.1.110:443-<--timeout  
...  
|S-chain|-<>-127.0.0.1:8080-<><>-192.168.1.110:445-<><>-OK  
...
```