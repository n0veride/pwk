
A raw socket is a type of socket that allows access to the underlying transport provider.  
They allow for surgical manipulation of TCP and UDP packets.  
  
Without access to raw sockets, Nmap is limited as it falls back to crafting packets by using the standard Berkeley socket API.  
  
Requires _**sudo**_ to access