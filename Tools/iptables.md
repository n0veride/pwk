

Admin tool for network packet filtering and NAT  
  
General format:  
```bash
iptables [-t table] [option] chain rulenum rule-specification
```

Chains include INBOUND and OUTBOUND  
Rule specification includes ACCEPT, REJECT and DROP  
  
**-I** - Insert new rule into a given chain  
**-s** - Specify a source IP addr  
**-d** - Specify a dest IP addr  
**-j** - Set rule  
**-Z** - Zero packet and byte counters  
**-v** - Verbose  
**-n** - Numberic output  
**-L** - List rules present in all chains