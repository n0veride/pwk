
omplex stream editor used to perform basic text tranformations on an input stream (a file or input from a pipeline).  
  
  
[https://catonmat.net/sed-one-liners-explained-part-one](https://catonmat.net/sed-one-liners-explained-part-one)  
  
Invokation:  
```bash
sed <script> <inputfile>
```

  
**-e** - Executes a script  
**-i** - Replace the file in-place  
  
Flags:  
**g** - Applies the replacement to all matches, not just the first  
  
Examples:   
To replace all occurrences of ‘hello’ to ‘world’ in the file input.txt:  
```bash
sed 's/hello/world/' input.txt > output.txt
```
 
To change a UUID of 1001 to 1014:  
```bash
sudo sed -i -e 's/1001/1014/g' /etc/passwd
```