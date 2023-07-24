
Web Server scanner that tests for dangerous files and programs, vuln server versions, and various server config issues.  
  
Not designed for stealth as it sends a lot of traffic and embeds info about itself in the User-Agent header.  
  
Can scan multiple servers, ports, and as many pages as it can find.  
  
  
Usage:  
```bash
nikto -host=<domain> -<options>=
```


**-Cgidirs** - Scans specified CGI directories. Special words "none" or "all" may be used to scan all CGI directories or none, (respectively)  
**-config** - Specify an alternative config file to use  
**-dbcheck** - Check the scan databases for syntax errors.  
**-Display** - Controls the output shown:  
		**1** - Show redirects  
		**2** - Show cookies received  
		**3** - Show all 200/ OK responses  
		**4** - Show URLs which require auth  
		**D** - Debut output  
		**V** - Verbose
**-evasion** - Specify the LibWhisker IDS evasion technique to use:  
		**1** - Random URI encoding (non-UTF8)  
		**2** - Directory self-reference ( /./ )  
		**3** - Premature URL ending  
		**4** - Prepend long random string  
		**5** - Fake parameter  
		**6** - TAB as request spacer  
		**7** - Change the case of the URL  
		**8** - Use Windows directory separator ( \ )  
**-findonly** - Only discover the HTTP(S) ports, do not perform a security scan.  
**-Format** - Save the output file specified with -o (-output) option in this format. If not specified, default will be taken from the file extension specified in the -output option.  
		**csv** - a comma-seperated list  
		**htm** - an HTML report  
		**txt** - a text report  
		**xml** - an XML report  
**-host** - Host(s) to target. Can be an IP address, hostname or text file of hosts. A single dash (-) maybe used for stdout. Can also parse nmap -oG style output  
**-Help** - Display extended help information.  
**-id** - ID and password to use for host Basic host authentication. Format is "id:password".  
**-list-plugins** - List all plugins that Nikto can run against targets and then exit. These can be tuned for a session using the -plugins option.  
		The output format is:  
			Plugin _name_  
			_full name_ - _description_  
			Written by _author_, Copyright (C) _copyright_  
**-mutate** - Specify mutation technique. A mutation will cause Nikto to combine tests or attempt to guess values.  
		These techniques may cause a tremendous amount of tests to be launched against the target.  
		Use the reference number to specify the type, multiple may be used:  
			**1** - Test all files with all root directories  
			**2** - Guess for password file names  
			**3** - Enumerate user names via Apache (/~user type requests)  
			**4** - Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)  
			**5** - Attempt to brute force sub-domain names, assume that the host name is the parent domain  
			**6** - Attempt to guess directory names from the supplied dictionary file  
**-mutate-options** - Provide extra information for mutates, e.g. a dictionary file  
**-nolookup** - Do not perform name lookups on IP addresses.  
**-nossl** - Do not use SSL to connect to the server.  
**-no404** - Disable 404 (file not found) checking. This will reduce the total number of requests but generally lead to more FPs.  
**-output** - Write output to the file specified. The format used will be taken from the file extension. This can be over-riden by using the -Format option. Existing files will have new information appended.  
**-plugins** - Select which plugins will be run on the specified targets. A comma separated list should be provided which lists the names of the plugins.  
		The names can be found by using -list-plugins. There are two special entries: ALL, which specifies all plugins shall be run and NONE, which specifies no plugins shall be run.  
		The default is ALL  
**-port** - TCP port(s) to target. Can be specified as a range (i.e., 80-90), or as a comma-delimited list, (i.e., 80,88,90). If not specified, port 80 is used.  
**-Pause** - Seconds to delay between each test.  
**-root** - Prepend the value specified to the beginning of every request. This is useful to test applications or web servers which have all of their files under a certain directory.  
**-ssl** - Only test SSL on the ports specified. Using this option will dramatically speed up requests to HTTPS ports, since otherwise the HTTP request will have to timeout first.  
**-Single** - Perform a single request to a target server. Nikto will prompt for all options which can be specified, and then report the detailed output. See Chapter 5 for detailed information.  
**-timeout** - Seconds to wait before timing out a request. Default timeout is 10 seconds.  
**-maxtime** - Halts the scan after the specified time limit. Doesn't optimize the scan, simply stops it.  
**-Tuning** - Tuning options will control the test that Nikto will use against a target:  
		**0** - File Upload  
		**1** - Interesting File / Seen in logs  
		**2** - Misconfiguration / Default File  
		**3** - Information Disclosure  
		**4** - Injection (XSS/Script/HTML)  
		**5** - Remote File Retrieval - Inside Web Root  
		**6** - Denial of Service  
		**7** - Remote File Retrieval - Server Wide  
		**8** - Command Execution / Remote Shell  
		**9** - SQL Injection  
		**a** - Authentication Bypass  
		**b** - Software Identification  
		**c** - Remote Source Inclusion  
		**x** - Reverse Tuning Options (i.e., include all except specified). The given string will be parsed from left to right, any x characters will apply to all characters to the right of the character.  
**-useproxy** - Use the HTTP proxy defined in the configuration file.  
**-update** - Update the plugins and databases directly from cirt.net.  
**-Version** - Display the Nikto software, plugin and database versions.  
**-vhost** - Specify the Host header to be sent to the target.