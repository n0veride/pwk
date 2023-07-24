

Fastest port scanner - created to scan the “entire internet” within 6 minutes. Great for scanning Class A and B subnets.  
Implements custom TCP/ IP stack and requries _sudo_'s access to raw sockets.  

  
**-p** - Specifies port  
**--rate** - Specifies desired rate of packet transmission  
**-e** - Specifies raw network interface to use (Ex: tap0)  
**--router-ip** - Specifies IP address for the appropriate gateway  
  
  
Ex:  
```bash
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
```