
The ability to selectively suspend the execution of jobs and resume their execution at a later time.  
  
  
**&** - Adding to the end of a command line automatically sends the process to the background  
  
**Ctrl + Z** - Suspends current running process  
  
**bg** - Resumes a currently suspended job in the background  
**fg** - Returns a job to the foreground  
**%**_number_ - Refers to a job number such as %1 or %2  
**%**_string_ - Refers to the beginning of the suspended command’s name such as **%**_commandNameHere_ or **%ping**  
**%+** OR **%\%** - Refers to the current job  
**%-** - Refers to the previous job  
  
**jobs** - Lists the jobs that are running in the current terminal session