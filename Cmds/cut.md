
Extract a section of text from a line and output it to STDOUT  
Can only use a single character delimiter  
  
  
**-d** - Denotes field delimiter  
**-f** - Denotes field number

```bash
echo "I hack binaries,web apps,mobile apps, and just about anything else"| cut -f 2 -d ","  
web apps  
  
cut -d ":" -f 1 /etc/passwd   
root   
daemon   
bin   
....
```