
An sh-compatible shell that allows us to run complex commands and perform different tasks from a terminal window.  
Incorporates useful features from both the KornShell (ksh)49 and C shell (csh)  
  
Each bash process has its own [environment variables](Env%20Vars.md).  
  
The Bash config file, _.bashrc_, is stored in the user's home directory  
Bash history is stored in the _.bash_history_ file in the user's home directory.  
  
History can be viewed with [history](history.md). HISTSIZE and HISTFILESIZE environment variables control the history size:  
**!!** - Reruns last command executed during the session  
**!**_n_ - Rerun _n_ command listed in Bash's history  
**!$** - Returns last word of the preceeding command  
**!*** - Retuns all arguments of preceeding command  
**Ctrl + R** - Invokes reverse-i-search facility. Start typing to get a match for the most recent command that contains that letter - continue typing to narrow down results or press again to cycle through earlier cmds  
  
  
**Command lists:**  
**;** - Executes commands in a chain  
**|** - Pipe - Passes the output of one command into the input of the next  
**&&** - AND - Executes the next command only if the previous one succeeded (returns True or 0)  
**||** - OR - Executes the next command only if the previous one failed (returns False or non-zero)

Ex **for**:  
```bash
for ip in (seq 1 10); do echo 10.11.1.$ip; done
```


**Sequence expression:**
**seq** - Print a sequence of numbers  
**{**_n_**..**_x_**}** - Brace expansion. Take the first _n_ and last _x_ value in a range of chars or numbers and iterates through the the range as a sequence.  

**sudo -i** -- Get root shell via current user's pw  
**su -** -- Get root shell via root's pw  
**sudo -l -l** -- Show allowed sudo cmds  


Prepend info to a file:
```bash
echo -e "data\n$(cat file)" > file
```
		adds “data” and newline to begining of <file>