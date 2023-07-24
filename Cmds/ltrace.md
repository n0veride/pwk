
Runs the specified command until it exits. 

It **intercepts and records the dynamic library calls which are called by the executed process and the signals which are received by that process**. It can also intercept and print the system calls executed by the program.


```bash
ltrace dpkg
```