

When a binary app is executed, it allocates memory within the memory boundaries used by modern computers.  
  
Lowest memory address (0x00000000) to highest memory (0x7FFFFFFF)

![[app_mem.png]]


**The Stack:**  
  
When a thread is running, it executes code from w/in the Program Image or from the DLLs.  
The short-term data area reserved for functions, local variables, and program control info is called the Stack.  
Each thread running has its own stack & can't access other thread's stacks.  
Allocate/ de-allocate's memory as needed, but only given small amount of space.  
  
Stack is a linear LIFO structure. x86 architecture impliments PUSH and POP instructions in order to add or remove data respectfully.  
  
When a thread calls a function, it needs to know which address to return to once the function completes.  
This ‘_Return Address_’, the function's params, and local variables are stored on the stack in a _Stack Frame_.  
Storage for data within a stack starts at high memory addresses moving to low memory addresses for next data storage, but data is written from low to high.

![[stack 1.png]]
  
**The Heap:**  
  
Long-term, more dynamic data storage area for global variables, objects, and other data accessible and visible to all threads.  
Only available while program is running, however does not allocate/ de-allocate automatically (must Delete)  
Larger memory space designated than stack