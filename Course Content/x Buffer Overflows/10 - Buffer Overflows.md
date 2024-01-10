

**Memory corruption vulnerability**. Exploit can be developed with a debugger - like [GDB](GDB.md) or [Immunity](Immunity%20Debugger.md)  
  
**Stack Smashing**: A form of vulnerability where the stack of a computer application or OS is forced to overflow “smashing” past/ through the func's storage space.  
  
[Stack](Program%20Memory.md)  
[CPU Registers](CPU%20Registers.md)  
Walkthroughs:
	Computerphile using [GDB](GDB.md): [https://www.youtube.com/watch?v=1S0aBV-Waeo](https://www.youtube.com/watch?v=1S0aBV-Waeo) John Hammon: [https://www.youtube.com/watch?v=YVlTDPhTA9U](https://www.youtube.com/watch?v=YVlTDPhTA9U)  
  
[Windows Buffer Overflows](11%20-%20BO%20Win.md)  
  
[Linux Buffer Overflows](12%20-%20BO%20Lin.md)  
  
  
  
Sample Vulnerable Code:  
```c
#include <stdio.h>  
#include <string.h>  
  
int main(int argc, char *argv[]){  
    char buffer[64];  
      
    if (argc < 2){  
        printf("Error - You must supply at least one argument\n");  
  
        return 1;  
    }  
      
    strcpy(buffer, argv[1];  
      
    return 0;  
}
```

- As the _buffer_ variable is defined w/in a function, it's a local variable, and the space (64-bytes) needed for it will be reserved within the _main_ function stack frame during its execution.  
- What happens when the cmdline argument passes exceeds 64 bytes?? Depends on size & data of included in the overflow  
	- Ex:
	![[strcpy80As.png]]

General Idea:
![[stack 1.png]]
When a program is run, each function receives its own stack:  
- First data written (highest memory address) is the _**calling function**_  
- Second are the function's passing _**parameters**_ (ie: char a, int b, etc)  
- Third is the _**return**_ address ([EIP register](CPU%20Registers.md)) which signals where outside of the function the code needs to return to for execution (how main() knows where to go after the function is finished)  
- Fourth is the _**base pointer**_ - references functions own stack frame  
- Fifth is the data the user enters into the program (ie: _**buffer**_)  
  
The goal is to write enough data (nop sled and shellcode) into the buffer so that we overwrite the base pointer and get the _**return**_ address to land us back inside the buffer where our shellcode is waiting:
![[buffer_overflow.png]]

**\\x90** - nop (move on to next instruction)  
  
So, the data we want to add to the buffer is a bunch of nop's (x/90) + shellcode + return pointer to middle of our nop sled (memory address for our eip register in backwards hex notation for little endian)  
  
Little endian requires backwards notation. So if memory address is 0xBFFFFABA, it must be written \\xBA\\xFA\\xFF\\xBF