
Wordlist generator for passwords  
  
  
Usage:  
```bash
crunch [ min ] [ max ] [ OPTIONS ]
```

Patterns:  
| Placeholder | Character Translation              |
| ----------- | ---------------------------------- |
| @           | Lower case alpha characters        |
| ,           | Upper case alpha characters        |
| %           | Numeric characters                 |
| ^           | Special characters including space |

Charset file can be located at: _/usr/share/crunch/charset.lst_  
  
**-f** - Specify charset file  
**-o** - Output file  
**-t** - Rule pattern  
  
More examples:  
```bash
crunch 4 6 0123456789ABCDEF -o crunch.txt  
	Crunch will now generate the following amount of data: 124059648 bytes  
	118 MB  
	0 GB  
	0 TB  
	0 PB  
	Crunch will now generate the following number of lines: 17891328   
  
	crunch: 100% completed generating output  
  
kali@kali:~$ head crunch.txt   
	0000  
	0001  
	0002  
	0003  
	0004  
	...
```

```bash
crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o crunch.txt  
	Crunch will now generate the following amount of data: 140712049920 bytes  
	134193 MB  
	131 GB  
	0 TB  
	0 PB  
	Crunch will now generate the following number of lines: 20158125312
```