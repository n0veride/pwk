

Easy SNMP scanner which sends requests for the sysDescr value (textual description of the SNMP entity) asynchronosly with user-adjustable sending times.  
  
Usage:  
```bash
onesixtyone <option> <host> <community>
```


**-c** _\<communityfile\>_ - Specifies a file with community names to try  
**-i** _\<inputfile\>_ - Specifies an input file with target hosts  
**-o** _\<outputfile\>_ - Specifies a logfile  
**-d** - Debug, can use twice for more info  
**-q** - Quiet mode (doesn't print to stdout)  
**-w** _\<n\> \<ms\>_ - Specifies wait between packets _n_ in milliseconds. Default 10.  
  

*SNMP community string is like a user ID or password that allows access to a router's, or other device's, statistics.