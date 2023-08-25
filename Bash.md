# Scripting

A Bash script is a plain-text file that contains a series of commands that are executed as if they had been typed at a terminal prompt.  
  
Bash scripts have an optional extension of .sh (for ease of identification).  
Begin with #!/bin/bash and must have executable permissions set before they can be executed.  
  
Ex:
```bash
#!/bin/bash -x  
# Hello World Bash script  
echo "Hello World!"
```

1) The **#!** (_shebang_) is ignored by the Bash interpreter. **/bin/bash** is the absolute path to the interpreter used to run the script. **-x** tells Bash to print out additional debug info  
1. This is what makes this a “Bash script” as opposed to another type of shell script, like a “C Shell script”, for example.  
2) The **#** is used for comments.  
3) **echo “Hello World!”** uses the **echo** Linux command utility to print a given string to the terminal.  

Once saved, the script will need to have **-x** added to its [permissions](Perms.md)


## Variables:
  
Declare variables: name=value (no spaces)  
Reference variable: $name  
  
Bash is case sensitive, and any value with spaces must be contained by either single or double quotes.  
  
**'** - Every enclosed character is interpreted literally  
**"** - All characters are interpreted literally except **$** (dollar sign), **`** (back tick), **\** (back slash)  
Variables will be expanded in an initial substitution pass on the enclosed text.  
  
Ex:
```bash
greeting='Hello World'  
echo $greeting  
        Hello World  
  
greeting2="New $greeting"  
echo $greeting2  
        New Hello World
```

Command substitution - Value of a variable can be set to result of a command or program  
  
name=$(cmd/program)  
• Can also use **`** (though the practise is deprecated) : name=`cmd/program`  
  
Ex:
```bash
user=$(whoami)  
echo $user  
        Kali
```

Using command substitution to redeclare variables:
```bash
#!/bin/bash -x  
  
var1=value1  
echo $var1  
  
var2=value2  
echo $var2  
  
$(var1=newvar1)  
echo $var1  
  
`var2=newvar2`  
echo $var2
```
• Happens in a subshell - **$(name=value)** OR **`name=value`**  
• Changes that happen w/in the subshell do not alter variables from the master process

Results:
```bash
+ var1=value1  
+ echo value1  
value1  
+ var2=value2  
+ echo value2  
value2  
++ var1=newvar1  
+ echo value1  
value1  
++ var2=newvar2  
+ echo value2  
value2
```
• Commands proceeded with a **+** executed in the current shell; Commands proceeded with **++** executed in a subshell


## Arguments:

```bash
#!/bin/bash  
  
echo "The first two args are $1 and $2"


chmod +x ./arg.sh  
./arg.sh Hello there!  
  
  
    The first two args are Hello and there!
```


Special Bash variables:

| Variable Name | Description                                      |
| ------------- | ------------------------------------------------ |
| $0            | The name of the Bash script                      |
| $1 - $9       | The first 9 arguments to the Bash script         |
| $#            | Number of arguments passed to the Bash script    |
| $@            | All arguments passed to the Bash script          |
| $?            | The exit status of the most recently run process |
| [$$]          | The PID of the current script                    |
| $USER         | The username of the user running the script      |
| $HOSTNAME     | The hostname of the machine                      |
| $RANDOM       | A random number                                  |
| $LINENO       | The current line number in the script            |


## Reading User Input:
  
**read** - Capture user input and assign it to a variable.  
**-p** - Specify a prompt  
**-s** - Makes user input silent  
  
Ex 1:
```bash
#!/bin/bash  
  
echo 'Hey there!  Would you like to play a game: Y/N?'  
  
read answer  
  
echo "Your answer is $answer"
```

Result 1:
```bash
Hey there!  Would you like to play a game: Y/N?  
  
        Y  
  
Your answer is Y
```

Ex 2:
```bash
#!/bin/bash  
#Prompt user for creds  
  
read -p 'Username: ' username  
read -sp 'Password: ' password  
  
echo "Thanks.  Your creds are as follows: " $username "and" $password
```

Result 2:
```bash
Username: user  
Password: Thanks.  Your creds are as follows:  user and pass
```


## If, Else, Elif:

**if** - Checks to see if a condition is true and executes command(s) if it is. Spaces are required syntax:
```bash
if [ <some test> ]  
then  
  <perform an action>  
fi
```

Ex **if**:
```bash
#!/bin/bash  
# if statement example  
  
read -p "What is your age: " age  
  
if [ $age -lt 16 ]  
then  
  echo "You might need parental permission to take this course!"  
fi
```
  
Result **if**:
```bash
What is your age: 14  
You might need parental permission to take this course!
```

Most common operators of the **test** command:

| Operator           | Description: Expression True if...    |
| ------------------ | ------------------------------------- |
| !EXPRESSION        | The EXPRESSION is false               |
| -n STRING          | STRING length is greater than zero    |
| -z STRING          | Length of STRING is zero (empty)      |
| STRING1 != STRING2 | STRING1 is not equal to STRING2       |
| STRING1 = STRING2  | STRING1 is equal to STRING2           |
| INT1 -ne INT2      | INT1 is not equal to INT2             |
| INT1 -eq INT2      | INT1 is equal to INT2                 |
| INT -gt INT2       | INT1 is greater than INT2             |
| INT1 -lt INT2      | INT1 is less than INT2                |
| INT1 -ge INT2      | INT1 is greater than or equal to INT2 |
| INT -le INT2       | INT1 is less than or equal to INT2    |
| -d FILE            | FILE exists and is a directory        |
| -e FILE            | FILE exists                           |
| -r FILE            | FILE exists and has the read perm     |
| -s FILE            | FILE exists and is not empty          |
| -w FILE            | FILE exists and has the write perm    |
| -x FILE            | FILE exists and has the execute perm  |

Ex **else**:
```bash
#!/bin/bash  
# else statement example  
  
read -p "What is your age: " age  
  
if [ $age -lt 16 ]  
then  
  echo "You might need parental permission to take this course!"  
else  
  echo "Welcome to the course!"  
fi
```

Result **else**:
```bash
What is your age: 21  
Welcome to the course!
```
  
Ex **elif**:
```bash
#!/bin/bash  
# elif statement example  
  
read -p "What is your age: " age  
  
if [ $age -lt 16 ]  
then  
  echo "You might need parental permission to take this course!"  
elif [ $age -gt 60 ]  
then  
  echo "Hats off to you.  Respect!"  
else  
  echo "Welcome to the course!"  
fi
```
  
Result **elif**:
```bash
What is your age: 65  
Hats off to you.  Respect!
```


## Boolean Logical Operators:

**&&** - AND  
**||** - OR  

Ex **&&**:
```bash
#/bin/bash   
# and example   
   
if [ $USER == 'kali' ] && [ $HOSTNAME == 'kali' ]  
then   
  echo "Multiple statements are true!"  
else   
  echo "Not much to see here..."  
fi
```
  
Ex **||**:
```bash
#/bin/bash   
# or example   
   
if [ $USER == 'kali' ] && [ $HOSTNAME == 'pwn' ]  
then   
  echo "One condition is true, this line is printed"  
else   
  echo "You are out of luck!"  
fi
```


## Loops:

**for** loops:  
```bash
for var_name in <list>  
do  
  <action to perform>  
done
```

Ex one-liner **for**:  
```bash
for ip in (seq 1 10); do echo 10.11.1.$ip; done
			OR
for ip in {1..10}; do echo 10.11.1.$ip; done
```

Result:  
```
10.11.1.1  
10.11.1.2  
10.11.1.3  
10.11.1.4  
10.11.1.5  
10.11.1.6  
10.11.1.7  
10.11.1.8  
10.11.1.9  
10.11.1.10
```

**while** loops:
```bash
while [ <some test> ]  
do  
  <perform an action>  
done
```
  
Ex **while** loop:
```bash
#!/bin/bash   
# while loop example   
   
counter=1   
   
while [ $counter -le 10 ]  
do   
  echo "10.11.1.$counter"  
  ((counter++))   
done
```
  
**(( ))** - Performs arithmetic expansion and evaluation at the same time.  


## Functions:

Two ways to write syntax:  
```bash
function function_name {  
  <commands>  
}

	OR

function_name () {  
  <commands>  
}
```

Passing args to functions:
```bash
#!/bin/bash  
# passing arguments to functions  
  
pass_arg() {  
  echo "Today's random number is: $1"  
}  
  
pass_arg $RANDOM
```

The parentheses are decorative - no arguments/ data types are put in there.  
Functions _must_ be defined before it's called.  
Functions can return an exit status and an arbitrary value accessed by the **$?** global variable.  
Global variables can be set inside a function or use command substitution to simulate a traditional function return.  

Ex:
```bash
#!/bin/bash  
# function return value example  
   
return_me() {  
  echo "Oh hello there, I'm returning a random value!"  
  return $RANDOM  
}  
  
return_me  
  
echo "The previous function returned a value of $?"
```
  
Result:
```
Oh hello there, I'm returning a random value!  
The previous function returned a value of 198
```

If the return statement is used without the $RANDOM argument, the exit status of the function (0 in this case) would be returned instead.  
  
Variable scope - can overlay a global variable within a function with **local**  
  
Ex:
```bash
#!/bin/bash  
# var scope example  
   
name1="John"  
name2="Jason"  
   
name_change() {  
  local name1="Edward"  
  echo "Inside of this function, name1 is $name1 and name2 is $name2"  
  name2="Lucas"  
}  
  
echo "Before the function call, name1 is $name1 and name2 is $name2"  
  
name_change  
  
echo "After the function call, name1 is $name1 and name2 is $name2"
```

Result:
```bash
Before the function call, name1 is John and name2 is Jason  
Inside of this function, name1 is Edward and name2 is Jason  
After the function call, name1 is John and name2 is Lucas
```  

Changing the value of a **local** variable with the same name as a global one will not affect its global value.

Changing the value of a global variable inside of a function – without having declared a **local** variable with the same name – will affect its global value.


# Shell

An sh-compatible shell that allows us to run complex commands and perform different tasks from a terminal window.  
Incorporates useful features from both the KornShell (ksh)49 and C shell (csh)  
  
Each bash process has its own [environment variables](Env%20Vars.md).  
  
The Bash config file, _.bashrc_, is stored in the user's home directory  
Bash history is stored in the _.bash_history_ file in the user's home directory.  
  
History can be viewed with [history](Cmdline%20Tools.md#history). HISTSIZE and HISTFILESIZE environment variables control the history size:  
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