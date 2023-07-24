
******NOT ALLOWED*******


Tests and exploits SQL Injection vulns.  
  
Saves reports in /home/kali/.local/share/sqlmap/output/<\domain\>  
  
***Note:** Always use “ ” around the domain  
  
  
Usage:  
```bash
python3 sqlmap -u "http://192.168.xxx.10/debug.php?id=1"
```

  
**-h**, **-hh** -        Show basic help message and exit  
**--version** -        Show program's version number and exit  
**-v** _<#>_ -        Verbosity level _#_: 0-6 (default 1)  
  
###### Target:
At least one of these options has to be provided to define the target(s)  
**-u** , **--url=** -        Target URL (e.g. "hXXp://www.site.com/vuln.php?id=1")  
**-g** _GOOGLEDORK_ -        Process Google dork results as target URLs  
  
###### Request:
These options can be used to specify how to connect to the target URL  
**--data=** -        Data string to be sent through POST (e.g. "id=1")  
**--cookie=** -        HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")  
-**-random-agent** -        Use randomly selected HTTP User-Agent header value  
**--proxy=** -        Use a proxy to connect to the target URL  
**--tor** -        Use Tor anonymity network  
**--check-tor** -        Check to see if Tor is used properly  
  
###### Injection:
These options can be used to specify which parameters to test for, provide custom injection payloads and optional tampering scripts  
**-p** -        Testable parameter(s)  
**--dbms=** -        Force back-end DBMS to provided value  
  
###### Detection:
These options can be used to customize the detection phase  
**--level=** -        Level of tests to perform (1-5, default 1)  
**--risk=** -        Risk of tests to perform (1-3, default 1)  
  
###### Techniques:
These options can be used to tweak testing of specific SQL injection techniques  
**--technique=** -        SQL injection techniques to use (default "BEUSTQ")  

###### Enumeration:
These options can be used to enumerate the back-end db management system information, structure and data contained in the tables  
**-a**, **--all** -        Retrieve everything  
**-b**, **--banner** -        Retrieve DBMS banner  
**--current-user** -        Retrieve DBMS current user  
**--current-db** -        Retrieve DBMS current database  
**--passwords** -        Enumerate DBMS users password hashes  
**--tables** -        Enumerate DBMS database tables  
**--columns** -        Enumerate DBMS database table columns  
**--dbs** -        Enumerate DBMS databases  
**--schema** -        Enumerate DBMS schema  
**--dump** -        Dump DBMS database table entries  
**--dump-all** -        Dump all DBMS databases tables entries  
**-D** -        DBMS database to enumerate  
**-T** -        DBMS database table(s) to enumerate  
**-C** -        DBMS database table column(s) to enumerate  
**--sql-shell** -        Prompt for an interactive SQL shell  
  
###### Operating system access:
These options can be used to access the back-end database management system underlying operating system  
**--os-shell** -        Prompt for an interactive operating system shell  
**--os-pwn** -        Prompt for an OOB shell, Meterpreter or VNC  
  
###### General:
These options can be used to set some general working parameters  
**--batch** - Never ask for user input, use the default behavior*****  
**--flush-session** - Flush session files for current target  
  
###### Miscellaneous:
These options do not fit into any other category  
**--wizard** -        Simple wizard interface for beginner users