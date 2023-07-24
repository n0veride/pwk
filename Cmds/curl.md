
Transfer data to or from a server using a host of protocols including IMAP/S, POP3/S, SCP, SFTP, SMB/S, SMTP/S, TELNET, TFTP, etc  

  
**-A** - Set User-Agent  
**-b** _\<name=value\>_ - Sets cookie to _name=value_ pair  
**-d** - Sends specified data in a POST request  
**-H** - Set request headers*  
**-I** - Grab headers only (sends HEAD request)  
**-i** - Display headers and the response body (sends any request we specify)  
**-k** - Skip TLS/ SSL cert check  
**-o** - Allows saving file to given directory/ file name.  
**-X** - Specify custom request method  
**-v** - Verbose. Allows viewing of full HTTP request and response  
**-u** _username:pw_ Login  
  
  
  
  
Setting the Content-Type so the webserver knows we're sending form data:
```bash
-H “Content-Type: application/x-www-form-urlencoded”
```