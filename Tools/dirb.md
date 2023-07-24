
Web content scanner that uses a wordlist to find directories and pages by issuing requests to the server  
Creates a lot of noise within log files though  
  
Can be customized to search for specific directories, use custom dictionaries, set a custom cookie or header on each request, etc  
  
Usage Ex:  
```bash
dirb <domain> <options>
```

**-a** - Specify your custom USER_AGENT  
**-b** - Use path as is  
**-c** - Set a cookie for the HTTP request  
**-E** - Set path to the client certificate  
**-f** - Fine tuning of NOT_FOUND (404) detection  
**-H** - Set custom header for the HTTP request  
**-i** - Use case-insensitive search  
**-l** - Print “Location” header when found  
**-N** - Specify HTTP code to ignore in responses  
**-o** - Output to file  
**-p** _\<proxy\[:port\]\>_ - Sets proxy and port. Default is 1080  
**-P** _\<proxy_username:proxy_password\>_ - Proxy Authentication  
**-r** - Turn off recursive searching  
**-R** - Interactive recursion (Asks for each directory)  
**-S** - Silent mode  
**-t** - Don't force an ending ‘/’ on URLs  
**-u** _\<username:password\>_ - HTTP Authentication  
**-v** - Verbose. Shows NOT_FOUND pages  
**-w** - Don't stop on WARNING messages  
**-x** _\<exts_file\>_ / **-X** _\<extenstions\>_ - Append each word with this extension(s)  
**-z** _\<#ms\>_ - Add a # millisecond delay to prevent excessive flooding.  
  
  
**DirBuster** is a Jave app similar to DIRB that offers multi-threading and a GUI interface.