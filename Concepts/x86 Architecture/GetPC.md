
Essentially a short routine that moves the value of the EIP register (sometimes referred to as the Program Counter or PC) into another register.  

  
As with other **GetPC** routines, those used by shikata_ga_nai have an unfortunate side-effect of writing some data at and around the top of the stack.  
  
This eventually mangles at least a couple of bytes close to the address pointed at by the ESP register.  
  
Unfortunately, this small change on the stack is a problem for us because the decoder starts exactly at the address pointed to by the ESP register.  
  
In short, the **GetPC** routine execution ends up changing a few bytes of the decoder itself (and potentially the encoded shellcode), which eventually fails the decoding process and crashes the target process.