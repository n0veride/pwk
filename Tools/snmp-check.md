
Similar tool to [snmpwalk](snmpwalk.md). Outputs in “very” human readable format.  
  
Usage Ex:  
```bash
snmp-check <options> <target ip>
```


**-p** - Specify port. Default is 161  
**-c** - Specify community. Default is public  
**-v** - Specify SNMP version. Default is 1  
**-w** - Detect write access  
**-d** - Disable TCP enumeration  
**-t** - Timeout in seconds. Default is 5  
**-r** - Request retries. Default is 1