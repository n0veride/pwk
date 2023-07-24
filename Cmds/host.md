
Queries DNS for domain name to IP address translation  
  
**-a** - Showes all DNS records available. Equivilant to **-v -t ANY**  
**-l** - Lists zone. Must add \<domain name\> \<dns server address\>
	Ex:
```bash
	host -l [domain] [nameserver]
```

**-p** - Specifies port on the server to query (default is 53)  
**-t** - Specifies DNS record to query (Default is A Record)  
**-v** - Verbose  
  
  
List zone: The host command performs a zone transfer of zone name and prints out the NS, PTR and address records (A/AAAA).  
Together, the **-l -a** options print all records in the zone.  
  
  
  
Ex: To find all namespaces:  
```bash
host -t ns [domain] | cut -d " " -f 4
```
  
Zone transfers:  
```bash
host -l [domain] [nameserver]
```
