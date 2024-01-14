
Database replication between related DNS servers in which the _zone file_ is copied from a master DNS server to a slave server.  
  
Zone Files contain a list of all the DNS names configured for that zone and should only be allowed to authorize slave DNS servers, but many admins misconfigure them so anyone can get a copy  
Worse misconfiguration is not separating internal DNS namespaces from external DNS namespaces into separate, unrelated zones. Allows for complete map of entire network structure.  
  
Port 53 needs to be open (queries _can_ be sent to non-standard port) & nameserver needs to be configured to allow zone transfers.  
  
Can attempt zone transfers with: [dig](OS%20Commands.md#dig), [host](OS%20Commands.md#host), [dnsenum](Tools.md#dnsenum), [dnsrecon](Tools.md#dnsrecon)