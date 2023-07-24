

Cross-compiler avilable on Linux


Install:
```bash
sudo apt install gcc-mingw-w64-i686
```
  
  
Usage Example:  
```bash
i686-w64-mingw32-gcc exploit.c -o exploit.exe
```

  
  
IF there is an error message: _undefined reference to `_imp__WSAStartup@8'_  
	Add **-lws2_32** at the end  
  
  
  
The above will compile a C script for Windows  
  
  
  
Also available for Windows & provides GCC  
  
Run the **mingw-w64.bat** script that sets up the _PATH_ environment variable for the gcc executable.  
	Once the script is finished, we can execute **gcc.exe** to confirm that everything is working properly:  
```powershell
C:\Program Files\mingw-w64\i686-7.2.0-posix-dwarf-rt_v5-rev1> mingw-w64.bat  
  
C:\Program Files\mingw-w64\i686-7.2.0-posix-dwarf-rt_v5-rev1>echo off  
	Microsoft Windows [Version 10.0.10240]  
	(c) 2015 Microsoft Corporation. All rights reserved.  
  
C:\> gcc  
	gcc: fatal error: no input files  
	compilation terminated.  
  
C:\> gcc --help  
	Usage: gcc [options] file...  
	Options:  
	-pass-exit-codes         Exit with highest error code from a phase.  
	--help                   Display this information.  
	...
```