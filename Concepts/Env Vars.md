

Form of global storage for various settings inherited by any applications that are run during that terminal session. Use **$** to reverence a variable.  
  
**$** - Variable that references PID of current shell interested (viewable w/ **$$**)  
**echo $**_variable_ - View contents of given variable  
[env](Cmdline%20Tools.md#env) - View defined environment variables (/usr/bin/env)  
[export](Cmdline%20Tools.md#export) - Define variables within Bash terminal that are accessable to any subprocesses spawned from current Bash instance.  
Setting a variable w/o **export** will only be available in the shell it was defined.  
  
HISTCONTROL - Controls whether or not to remove duplicate commands, commands that begin with spaces from the history, or both. (Default is both)  
```bash
export HISTCONTROL=ignoredups
```
	- Ignores just dupes.  

```bash
export HISTIGNORE="&:ls:[bf]g:exit:history"
```
	- Ignores basic commands run frequently like **ls**, **exit**, **history**, **bg**, etc  

HISTSIZE - Controls number of commands stored in memory for the current session  
HISTFILESIZE - Configures number of commands kept in the history file  
HISTTIMEFORMAT - Controls date and/or time stamps in the output. Formats can be found in the **strftime** man page  
	%F (Year-Month-Day ISO 8601 format)  
	%T (24-hour time)