
Domain Name System - Distributed database responsible for translating domain names into IP addresses. Can query with [host](Cmdline%20Tools.md#host) command  
  
Now, when talking about domain names, it's important to know about the ROOT - www[.]example[.]com_**.**_ <----- That last . after “com” signals the root server - very top level of the DNS hierarchy.  
  
  
_**DNS caching**_ is used to store local copies of DNS records at various stages of the lookup process to facilitate performance and reliability.  
_**Zone File**_ - Where all the DNS records are stored for a domain  
_**Host Record**_ - Domain or subdomain you wish to use. The @ symbol is used to indicate the root domain itself.  
Ex: ftp.google.com The Host Record ‘ftp’ would be for the subdomain and ‘@’ would be google.com itself.  
_**TTL**_ - Time to Live. Value that indicates the amount of time the record is cached by a DNS Server (such as your ISP) Default (& lowest accepted) is 14400 seconds (4 hrs)  
_**Weight**_ - Similar to priority. Controls the order in which multiple records are used. Lower numbers are used before higher numbers (as with MX Entries)  
  
  ![[DNS.png]]

1. Hostname is entered into a browser/ app which passes hostname to the OS's DNS client - the _**DNS Resolver**_ (Layer 2 or 3)  
◇ DNS Cache locations are checked and updated throughout the process (Above ex: 2, 15, 4, 13)  
3. Which is then forwarded to the external DNS server it's configured to use - _**DNS Recursor**_  
◇ DNS Recursor is responsible for interacting w/ the DNS infrastructure and returning the results to the DNS client.  
5. DNS Recursor contacts one of the servers in the DNS root zone.  
6. Root server then responds with the address of the server responsible for the zone containing the TLD.  
7, 8, 9. Once DNS Recursor receives the address of the TLD DNS server, it queries it for the address of the _**Authoritative Nameserver**_ for that domain.  
◇ The authoritative nameserver contains the DNS records in a local database known as the _**zone file**_  
◇ Typically hosts two zones for each domain:  
▪ Forward lookup zone used to find the IP address of a specific hostname  
▪ Reverse lookup zone used to find the hostname of a specific IP address - _**PTR Record**_ (if admin configured)  
12, 14, 16. Once DNS Recursor provides the DNS client w/ the IP address, the browser can contact the correct web server at its IP address and load the webpage.