


Used for finding the opcode equivalent of assembly.  
  
  
  
Ex: Finding opcode for **JMP ESP** gives opcode of 0xFFE4  
```bash
┌──(kali㉿kali)-[~/temp]  
└─$ msf-nasm_shell                         
nasm > jmp esp  
00000000  FFE4              jmp esp  
nasm > 
```


Opcode for **ADD EAX** of 12 bytes give opcode of 0x83C00C  
```bash
kali@kali:~$ msf-nasm_shell  
  
nasm > add eax,12  
00000000  83C00C            add eax,byte +0xc
```