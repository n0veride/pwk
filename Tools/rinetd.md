

Port forwarding tool. Easily configurable.  
  
  
Config file: **/etc/rinetd.conf**:
```bash
# forwarding rules come here  
#  
# you may specify allow and deny rules after a specific forwarding rule  
# to apply to only that forwarding rule  
#  
# bindadress  bindport  connectaddress  connectport  options...  
# 0.0.0.0     80        192.168.1.2     80  
# ::1         80        192.168.1.2     80  
# 0.0.0.0     80        fe80::1         80  
# 127.0.0.1   4000      127.0.0.1       3000  
# 127.0.0.1   4000/udp  127.0.0.1       22           [timeout=1200]  
# 127.0.0.1   8000/udp  192.168.1.2     8000/udp     [src=192.168.1.2,timeout=1200]
```

_bindaddress_ & _bindport_ - define the bound ("listening") IP address & port.  
  
_connectaddress_ & _connectport_ - define the traffic's destination address & port.  
  
restart service:  
```bash
sudo service rinetd restart  
  
ss -antp | grep "80"  
LISTEN 0      128            0.0.0.0:80           0.0.0.0:*
```


Run on attack/ compromised web server & connect to whichever site is entered for _connectaddress/port_ by connecting from the non-internet vic to the attack/ compromised web server.