
DNS Lookup utility

Usage:
```bash
dig <type> <domain> <addt options>
```


**-b** - Specify source IP address  
**-m** - Enable memory usage debugging  
**-p** - Send query to non-standard port  
**-q** - Domain name to query (useful when needing to distinguish from other arguments)  
**-v** - Print version number and exit  
**-x** _addr_ - Use Reverse Lookup on given IP _addr_  
**ANY** - Queries all available record types  
**+\[no\]stats** - Toggles printing of statistics  
**+\[no\]cmd** - Toggles initial comment (ID'ing the version of dig and the query options) in the output  
**+\[no\]comments** - Toggles display of some comment lines (packet header, etc) in the output


Zone transfers:
```bash
dig [domain] ANY +nostat +nocmd +nocomments
			OR
dig [domain] @[nameserver]
```