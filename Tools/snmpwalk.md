

Uses SNMP GETNEXT requests to probe and query a network entity for tree values. Need to know the read-only community string (most cases “public”)  
  
An OID (object identifier) may be given on the cmd line specifying which portion of the OID space will be searched.  
  
Usage:  
```bash
snmpwalk <options> <target ip> <OID>
```


**-c** - Specify community string  
**-v** - Specify the SNMP version number  
**-t** _\<n\>_- Specify timeout period to _n_ seconds  
**-Cc** - Disable ascending OID check. Some agents (like LaserJets) return OIDs out of order.  
**-Cp** - Print the number of variables found.