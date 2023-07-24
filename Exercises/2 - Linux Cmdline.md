
###### 2.4.4.5
Use find to identify any file (not directory) modified in the last day, NOT owned by the root user, and execute ls -l on them. Chaining/piping commands is NOT allowed!  
```bash
find / -mtime -1 -not -type d -and -not -user root 2>/dev/null -exec sh -c 'ls -l' {} +  
find / -type d -user root -prune -o -mtime -1 -print -exec sh -c 'ls -l' {} +
```
	 ^wasn't working

```bash
find . -mtime -1 ! -type d ! -user root 2>/dev/null -exec sh -c "ls -l {}" ';'
```
	^worked