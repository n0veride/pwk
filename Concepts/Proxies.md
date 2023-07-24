
A proxy is when a device or service sits in the middle of a connection and acts as a mediator.  
The mediator is the critical piece of information because it means the device in the middle must be able to inspect the contents of the traffic.  
Without the ability to be a mediator, the device is technically a gateway, not a proxy.  
  
So... VPNs are technically not proxies.  
  
_**FoxyProxy**_ (262 - 271) is a Firefox add-on that allows for easy setting and manipulating proxies.  
  
  
##### Forward Proxies:  
  
A Forward Proxy is when a client makes a request to a computer, and that computer carries out the request.  
  
For example, in a corporate network, sensitive computers may not have direct access to the Internet.  
To access a website, they must go through a proxy (or web filter).  
This can be an incredibly powerful line of defense against malware, as not only does it need to bypass the web filter (easy), but it would also need to be proxy aware or use a non-traditional C2.  
If the organization only utilizes FireFox, the likelihood of getting proxy-aware malware is improbable.  
  
Web Browsers like Internet Explorer, Edge, or Chrome all obey the "System Proxy" settings by default.  
If the malware utilizes _WinSock_ (Native Windows API), it will likely be proxy aware without any additional code.  
Firefox does not use _WinSock_ and instead uses **libcurl**, which enables it to use the same code on any operating system.  
This means that the malware would need to look for Firefox and pull the proxy settings, which malware is highly unlikely to do.  
  
  
##### Reverse Proxies:  
  
Rather than filtering outbound traffic, they filter inbound traffic.  
  
The most common goal with a Reverse Proxy, is to listen on an address and forward it to a closed-off network.  
  
Many organizations use CloudFlare as they have a robust network that can withstand most DDOS Attacks.  
By using Cloudflare, organizations have a way to filter the amount (and type) of traffic that gets sent to their webservers.  
  
Penetration Testers will configure reverse proxies on infected endpoints:  
The infected endpoint will listen on a port and send any client that connects to the port back to the attacker through the infected endpoint.  
This is useful to bypass firewalls or evade logging. Organizations may have IDS (Intrusion Detection Systems), watching external web requests.  
If the attacker gains access to the organization over SSH, a reverse proxy can send web requests through the SSH Tunnel and evade the IDS.  
  
Another common Reverse Proxy is ModSecurity, a WAF.