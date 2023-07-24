
A programming language designed for text processing and is typically used as a data extraction and reporting tool.  
Can have multiple character delimiter.  
  
**$**_n_ - Denotes field number  
**-F** - Field separator

```bash
echo "hello::there::friend" | awk -F "::" '{print $1, $3}'  
	hello friend
```

Sort file text by length:
```bash
awk '{print length(), $0 | "sort -n"}' values_and_flags.txt
```