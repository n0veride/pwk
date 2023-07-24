

[https://wiki.osdev.org/CPU_Registers_x86](https://wiki.osdev.org/CPU_Registers_x86)  


To find the opcode equivalent of assembly code (ex: **JMP ESP**), you can use **msf-nasm_shell**  
  
  
Registers are small, extremely high-speed CPU storage locations for data to be efficiently read or manipulated.  
  
For efficient code execution, CPU maintains and uses a series of nine 32-bit registers for an x86 Architecture (32-bit platform) and sixteen 64-bit registers for and x86_64 Architecture.  
Grouped into 3 categories:  
- General
	- Data
	- Pointer
	- Index
- Control
- Segment
  

### Data Registers:

Used for arithmetic, logical, and other operations  
- **EAX** - Accumulator register  
	- Used in input/ output, most arithmetic and logical instructions, interrupt calls, etc  
-  **EBX** - Base register  
	- Used in indexed addressing as a base pointer for memory access  
- **ECX** - Count register  
	- Used as a loop, shift, and rotation counter  
- **EDX** - Data register  
	- Used in input/ output, multiplication/ division, some interrupt calls  
  

### Pointer Registers:

- **EIP** - Intruction Pointer  
	- Stores the offset address of the next instruction to be executed.  
	- Directs the flow of a program  
		- **Primary target for memory corruption exploits** ie: [Buffer Overflows](PWK--Strat--10_Buffer_Overflows.html)  
	- In association w/ the ECS register (CS:IP) gives the complete address of the current instruction in the code segment  
- **ESP** - Stack Pointer  
	- Stores the offset value within the program stack.  
	- In association w/ the ESS register (SS:SP) gives the current position of data or address w/in the program stack  
- **EBP** - Base Pointer  
	- Stores pointer to top of the stack when a function is called allowing easy reference from its own stack frame while executing  
	- Address in ESS register is combined w/ the offset in the BP to get the location of the parameter  
	- Can also be combined w/ EDI and ESI as base register for special addressing  


### Index Registers:
 
Used for indexed addressing and sometimes used in addition and subtraction  
- **ESI** - Source Index  
	- Used as source index for string operations  
- **EDI** - Destination Index  
	- Used as destination index for string operations  


### Control Registers:


### Segment Registers:

Areas defined in a program for containing data, code, and stack  
- **ECS** - Code Segment  
	- Contains all the instructions to be executed.  
- **EDS** - Data Segment  
	- Contains data, constants, and work areas  
- **ESS** - Stack Segment  
	- Contains data and return addresses of procedures or subroutines.  
	- Implemented as a ‘stack’ data structure  
	- Stores the starting address of the stack