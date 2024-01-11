

# 10.2.5.7

This challenge will assess your understanding of the stack in program memory.  
Log in to the target machine VM #5 via RDP with the provided credentials.  
On this user's desktop, you will find a binary named **example.exe** and two text files with C source code snippets:  
**example.c.txt** and **push_and_pop.c.txt**.  
To solve this challenge, first study the example code and then observe its execution by running the example.exe program from a Command Prompt window.  
With a good understanding of how the stack works in memory, turn your attention to the push_and_pop.c.txt file.  
The flag is the value that would be printed when this program is executed.  
You can assume that _stack_, _push_ and _pop_ are appropriately defined functions and work as expected.  
**NOTE:** the flag's hexadecimal values present in the **push_and_pop.c.txt** file do not require any further conversion prior to submission.

push_and_pop.c.txt:
```C
#include <stdio.h>  
  
int main() {  
     
    struct Stack* stack = createStack(100);  
  
    char *a, *b, *c, *d;  
    char *value1 = "\x03\x02\xe1\x80";  
    char *value2 = "\x5a\x0f\x16\x5d";  
    char *value3 = "\x70\x95\x00\xa7";  
    char *value4 = "\xda\xa8\xad\xbd";  
    char *value5 = "\x49\xcc\xe1\xff";  
    char *value6 = "\xd7\xd8\x69\xac";  
    char *value7 = "\x87\x41\xe3\x71";  
  
    push(stack, value1);  
    push(stack, value2);  
    a = pop(stack);  
    push(stack, value3);  
    push(stack, value4);  
    b = pop(stack);  
    push(stack, value5);  
    push(stack, value6);  
    c = pop(stack);  
    push(stack, value7);  
    d= pop(stack);  
  
    printf("The flag is OS{");  
    printf("%s%s%s%s", a,b,c,d);  
    printf("}\r\n");  
  
    return 0;  
}
```
	a = value 2  
	b = value 4  
	c = value 6  
	d = value 7  
  
answer = OS{5a0f165ddaa8adbdd7d869ac8741e371}