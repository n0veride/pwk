
The _Portable Executable_ (_PE_)[1](https://portal.offensive-security.com/courses/pen-200/books-and-videos/modal/modules/antivirus-evasion/methods-of-detecting-malicious-code/methods-of-detecting-malicious-code#fn1) file format isused on Windows operating systems for executable and object files.  
  
The PE format represents a Windows data structure that details the information necessary for the  
Windows loader[2](https://portal.offensive-security.com/courses/pen-200/books-and-videos/modal/modules/antivirus-evasion/methods-of-detecting-malicious-code/methods-of-detecting-malicious-code#fn2) to manage the wrapped executable code including required dynamic libraries, API imports and exports tables, etc.  
  
  
Import Address Tables (_IAT_):  
  
Comprised of function pointers, ans is used to get the addresses of functions when the DLLs are loaded.