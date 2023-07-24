

PW cracking tool.  
  
**Uses GPU for cracking rather than CPU (john)  

Combinator:  
```bash
cewl www.megacorpone.com -m 12 -w cewl-megacorp.txt  
crunch 3 3 %%% > numbers.txt  
hashcat –m 1400 –a 1 flag.hash cewl-megacorp.txt numbers.txt
```