

Python script w/in Immunity Debugger that can be used to automate and speed up specific searches while developing exploits  
  
```bash
!mona help <command>  
!mona modules  
!mona find -s "<opcode>" -m "<DLL/module name>"  
!mona update
```


Shows memory space of all DLLs or modules loaded by attached process  
  
Column ouput includes:  
  
Base | Top Mem addresses Size of module | Flag values | Module version, Module name, & Path