
# OSINT

### whois

Client for the whois directory service.  Used for getting IP addressing/ hosts of a target.

Usage:
```bash
whois <option> <object>
```

| Options              |                                                      |
|:-------------------- |:---------------------------------------------------- |
| -h HOST, --host HOST | Connect to server HOST                               |
| -p PORT, --port PORT | Connect to PORT                                      |
| -I                   | Query whois.iana.org and follow its referral         | 
| -H                   | Hide legal disclaimers                               |
| --verbose            | Explain what is being done                           |
| --no-recursion       | Disable recursion from registry to registrar servers |
| --help               | Display this help and exit                           |
| --version            | Output version information and exit                  |

These flags are supported by whois.ripe.net and some RIPE-like servers:

| Options |  |
| :--- | ---- |
| -l | Find the one level less specific match |
| -L | Find all levels less specific matches |
| -m | Find all one level more specific matches |
| -M | Find all levels of more specific matches |
| -c | Find the smallest match containing a mnt-irt attribute |
| -x | Exact match |
| -b | Return brief IP address ranges with abuse contact |
| -B | Turn off object filtering (show email addresses) |
| -G | Turn off grouping of associated objects |
| -d | Return DNS reverse delegation objects too |
| -i ATTR... | Do an inverse look-up for specified ATTRibutes |
| -T TYPE... | Only look for objects of TYPE |
| -K | Only primary keys are returned |
| -r | Turn off recursive look-ups for contact information |
| -R | Force to show local copy of the domain object even if it contains referral |
| -a | Also search all the mirrored databases |
| -s SOURCE... | Search the database mirrored from SOURCE |
| -g SOURCE:FIRST-LAST | Find updates from SOURCE from serial FIRST to LAST |
| -t TYPE | Request template for object of TYPE |
| -v TYPE | Request verbose template for object of TYPE |
| -q \[version, sources, types\] | Query specified server info |

### Google Dorks

 [Google Hacking Database GHDB](https://www.exploit-db.com/google-hacking-database)
 [Dork Search portal](https://dorksearch.com/) - Provides a pre-built subset of queries and a builder tool to facilitate the search.

Useful -

File type:
```bash
site:megacorpone.com filetype:php
site:megacorpone.com -filetype:html
site:megacorpone.com ext:php
site:megacorpone.com ext:xml
site:megacorpone.com ext:py
```
	Finds, in order: PHP pages, all pages that *aren't* html, PHP pages, XML pages, Python pages.


Subdomains:
```console
site:*megacorpone.com -site:www.megacorpone.com
```

Search for specific strings
```bash
intitle:“index of” “parent directory”
```
	Find pages that contain "index of" in the title and the words "parent directory" on the page


### [Netcraft](https://searchdns.netcraft.com)

Free web portal that performs various information gathering functions.
Reports on:
- Network Info
- IP Delegation
- SSL/TLS info
- Hosting History
- Web Trackers
- App Servers
- Server/ Client-side Technologies
- Client-side Scripting Frameworks
- etc

Enter in the domain and click on the Site Report button.

Also useful:   List of companies' tech stacks: [stackshare.io](https://stackshare.io)

### GitLeaks

[https://github.com/zricethezav/gitleaks](https://github.com/zricethezav/gitleaks)  
  
SAST tool for detecting and preventing hardcoded secrets like passwords, api keys, and tokens in git repos.  
  
**--repo-url=** - Assign github repo site to clone and scan (depends on version??)

![[gitleaks.png|800]]

### GitRob

[https://github.com/michenriksen/gitrob](https://github.com/michenriksen/gitrob)  
  
Tool to help find potentially sensitive files pushed to public repositories on Github.  
Clones repositories belonging to a user or organization down to a configurable depth and iterate through the commit history and flag files that match signatures for potentially sensitive files.  
The findings will be presented through a web interface for easy browsing and analysis.


### [Shodan.io](https://www.shodan.io)

Search engine that crawls devices connected to the internet.     Can find servers, RDP open ports, routers, IoT devices, etc.
Requires login acct.
  
Can use filters when searching:
```bash
hostname:megacorpone.com
port:"22"
```

Clicking on any IP w/in the search results will net:
- General Info
- Web Technologies
- Info on any open ports
- Vulnerabilities

![[shodan_ip.png|800]]


### [Security Headers](https://securityheaders.com/)

Analyzes HTTP response headers and provide basic analysis of the target site's security posture.
Gives you an idea on an org's coding and security practices and possible attack vectors.

![](security_headers.png)

### [SSL Labs](https://www.ssllabs.com/ssltest/)

Analyzes a server's SSL/TLS configuration and compares it against current best practices.
Can also ID vulnerabilities like [POODLE](https://en.wikipedia.org/wiki/POODLE) and [HEARTBLEED](https://en.wikipedia.org/wiki/Heartbleed)

![](ssl_labs.png)


### Removed from course:

#### recon-ng

Module based framework for web-based OSINT.  Displays results to terminal and saves to a database which can feed into other modules.  
Can tab-complete.  
\*Leaving the source option set to default will try to pull from all possibilities w/in the database

| Options              | Desc                                                                                                                                     |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **marketplace**      | Used to install modules<br>Modules w/ * in the ‘K' column displays which modules require credentials or API keys for 3rd party providers |
| **search**           | Searches for given module                                                                                                                |
| **info**             | Gives info such as path, author, version, last updated, description, dependencies, etc etc.                                              |
| **install**          | Installs given module                                                                                                                    |
| **modules** **load** | Loads given module                                                                                                                       |
| **info**             | Gives details and requirements of loaded module                                                                                          |
| **options set**      | - Sets options of given loaded module (similar to Metasploit)                                                                            |
| **run**              | Run module                                                                                                                               |
| **back**             | Exit currently loaded module                                                                                                             |
| **show**             | Shows database categories                                                                                                                |
| **hosts**            | Shows hosts discovered (ex: from _recon/domains-hosts/google_site_web_ module)                                                           |
  
Can import [nmap](nmap.md) (& other tools) to ingest its output into recon-ng's database. Allows you to keep the work done w/in Nmap

#### [pastebin](https://pastebin.com)

Used for storing and sharing text. Search was removed, so have to use google dorks for results

#### theHarvester

Gather OSINT on company or domain. Useful for email harvesting. (got version 3.2.3 working on Parrot, but not 4.0.0 on Kali. bing works better on Kali v4.0.3)

Usage:
```console
theHarvester [-h] -d DOMAIN [-l LIMIT] [-S START] [-p] [-s] [--screenshot SCREENSHOT] [-v]
	[-e DNS_SERVER] [-t] [-r [DNS_RESOLVE]] [-n] [-c] [-f FILENAME] [-b SOURCE]
```

| Options | Desc |
| ---- | ---- |
| -h, --help | show this help message and exit |
| -d DOMAIN<br>--domain DOMAIN | Company name or domain to search. |
| -l LIMIT<br>--limit LIMIT | Limit the number of search results, default=500. |
| -S START, --start START | Start with result number X, default=0. |
| -p, --proxies | Use proxies for requests, enter proxies in proxies.yaml. |
| -s, --shodan | Use Shodan to query discovered hosts. |
| --screenshot SCREENSHOT | Take screenshots of resolved domains specify output<br>directory: --screenshot output_directory |
| -v<br>--virtual-host | Verify host name via DNS resolution and search for virtual hosts. |
| -e DNS_SERVER<br>--dns-server DNS_SERVER | DNS server to use for lookup. |
| -t<br>--take-over | Check for takeovers. |
| -r \[DNS_RESOLVE]<br>--dns-resolve \[DNS_RESOLVE] | Perform DNS resolution on subdomains with a resolver list or passed in resolvers, default False. |
| -n<br>--dns-lookup | Enable DNS server lookup, default False. |
| -c<br>--dns-brute | Perform a DNS brute force on the domain. |
| -f FILENAME<br>--filename FILENAME | Save the results to an XML and JSON file. |
| -b SOURCE<br>--source SOURCE | anubis, baidu, bevigil, binaryedge, bing, bingapi, bufferoverun, brave, censys, certspotter,<br>criminalip, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, hackertarget, hunter,<br>hunterhow, intelx, netlas, onyphe, otx, pentesttools, projectdiscovery, rapiddns, rocketreach,<br>securityTrails, sitedossier, subdomaincenter, subdomainfinderc99, threatminer,<br>tomba, urlscan, virustotal, yahoo, zoomeye |


#### [social-searcher](https://www.social-searcher.com)

Social media search engine.
Search across social media for keywords and users

#### [haveibeenpwned.com/PwnedWebsites](https://haveibeenpwned.com/PwnedWebsites) 

Contains info on breached websites.

#### twofi
Scans a user's Twitter feed and generates a personalized wordlist used for password attacks against that user.  
Requires valid Twitter API key  [digi.ninja/projects/twofi.php](http://digi.ninja/projects/twofi.php)

Usage:
```bash
twoif [OPTIONS]
```

| Options | Desc |
| ---- | ---- |
| --h<br>-help | Show help |
| --config \<file> | Config file, default is twofi.yml |
| -c<br>--count | include the count with the words |
| -m<br>--min_word_length | minimum word length |
| -T \<file><br>--term_file | Afile containing a list of terms |
| -t<br>--terms | Comma separated search terms quote words containing spaces, no space after commas |
| -U \<file><br>--user_file | A file containing a list of users |
| -u<br>--users | Comma separated usernames quote words containing spaces, no space after commas |
| -v<br>--verbose | verbose |


#### linkedin2username

Script for generating username lists based on LinkedIn data.  
Requires valid LinkedIn creds and depends on a connection to individuals in the target org.  
  
[github.com/inistring/linkedin2username](http://github.com/inistring/linkedin2username)

#### [OSINT Framework](https://osintframework.com)

Includes info gathering tools and websites in one central location 

#### [maltego](https://www.maltego.com/maltego-community/)

Powerful data mining tool that uses “transforms” that takes a bit of data (ex: email address) and links it w/ other associated data (ex: phone number, street add, etc)

# Active Info Gathering

## DNS
### host

Queries DNS for domain name to IP address translation

Usage:
```bash
host [-aCdilrTvVw] [-c class] [-N ndots] [-t type] [-W time] [-R number] [-m flag] [-p port] hostname [server]
```

| Options | Desc |
| ---- | ---- |
| -a | Equivalent to **-v -t ANY** |
| -A | Similar to **-a**  but omits RRSIG, NSEC, NSEC3 |
| -c | Specifies query class for non-IN data |
| -C | Compares SOA records on authoritative nameservers |
| -d | Equivalent to **-v** |
| -l | Lists all hosts in a domain, using AXFR |
| -m | Set memory debugging flag (trace\|record\|usage) |
| -N | Changes the number of dots allowed before root lookup is done |
| -p | Specifies the port on the server to query |
| -r | Disables recursive processing |
| -R | Specifies number of retries for UDP packets |
| -s | A SERVFAIL response should stop query |
| -t | Specifies the query type |
| -T | Enables TCP/IP mode |
| -U | Enables UDP mode |
| -v | Enables verbose output |
| -V | Print version number and exit |
| -w | Specifies to wait forever for a reply |
| -W | Specifies how long to wait for a reply |
| -4 | Use IPv4 query transport only |
| -6 | Use IPv6 query transport only |

### dnsrecon

Enumeration script written in Python

Usage:
```bash
dnsrecon [-h] [-d DOMAIN] [-n NS_SERVER] [-r RANGE] [-D DICTIONARY] [-f] [-a] [-s] [-b] [-y] [-k] [-w] [-z] [--threads THREADS]
     [--lifetime LIFETIME] [--tcp] [--db DB] [-x XML] [-c CSV] [-j JSON] [--iw] [--disable_check_recursion]
     [--disable_check_bindversion] [-V] [-v] [-t TYPE]
```

| Options | Desc |
| ---- | ---- |
| -h<br>--help | show this help message and exit |
| -d DOMAIN<br>--domain DOMAIN | Target domain |
| -n NS_SERVER<br>--name_server NS_SERVER | Domain server to use. If none is given, the SOA of the target will be used. Multiple servers can be specified using a comma separated list |
| -r RANGE<br>--range RANGE | IP range for reverse lookup brute force in formats   (first-last) or in (range/bitmask) |
| -D DICTIONARY<br>--dictionary DICTIONARY | Dictionary file of subdomain and hostnames to use for brute force |
| -f | Filter out of brute force domain lookup, records that resolve to the wildcard defined IP address when saving records |
| -a | Perform AXFR with standard enumeration. |
| -s | Perform a reverse lookup of IPv4 ranges in the SPF record with standard enumeration |
| -b | Perform Bing enumeration with standard enumeration |
| -y | Perform Yandex enumeration with standard enumeration |
| -k | Perform crt.sh enumeration with standard enumeration |
| -w | Perform deep whois record analysis and reverse lookup of IP ranges found through Whois when doing a standard enumeration |
| -z | Performs a DNSSEC zone walk with standard enumeration |
| --threads THREADS | Number of threads to use in reverse lookups, forward lookups, brute force and SRV record enumeration |
| --lifetime LIFETIME | Time to wait for a server to respond to a query. default is 3.0 |
| --tcp | Use TCP protocol to make queries |
| --db DB | SQLite 3 file to save found records |
| -x XML<br>--xml XML | XML file to save found records |
| -c CSV<br>--csv CSV | Save output to a comma separated value file |
| -j JSON<br>--json JSON | save output to a JSON file |
| --iw | Continue brute forcing a domain even if a wildcard record is discovered |
| --disable_check_recursion | Disables check for recursion on name servers |
| --disable_check_bindversion | Disables check for BIND version on name servers |
| -V<br>--version | Show DNSrecon version |
| -v<br>--verbose | Enable verbose |
| -t TYPE<br>--type TYPE | Type of enumeration to perform |
| **Possible Types:** |  |
|  | std:      SOA, NS, A, AAAA, MX and SRV. |
|  | rvl:      Reverse lookup of a given CIDR or IP range. |
|  | brt:      Brute force domains and hosts using a given dictionary. |
|  | srv:      SRV records. |
|  | axfr:     Test all NS servers for a zone transfer. |
|  | bing:     Perform Bing search for subdomains and hosts. |
|  | yand:     Perform Yandex search for subdomains and hosts. |
|  | crt:      Perform crt.sh search for subdomains and hosts. |
|  | snoop:    Perform cache snooping against all NS servers for a given domain,<br>testing all with file containing the domains, file given with -D option. |
|  | tld:      Remove the TLD of given domain and test against all TLDs registered in IANA. |
|  | zonewalk: Perform a DNSSEC zone walk using NSEC records. |

### dnsenum
Multi-threaded script to enumerate information on a domain and to discover non-contiguous IP blocks

Usage:
```bash
dnsenum [Options] <domain>
```

| Options | Desc |
| ---- | ---- |
| --dnsserver \<server> | Use this DNS server for A, NS and MX queries. |
| --enum | Shortcut option equivalent to **--threads 5 -s 15 -w**. |
| -h<br>--help | Print this help message. |
| --noreverse | Skip the reverse lookup operations. |
| --nocolor | Disable ANSIColor output. |
| --private | Show and save private ips at the end of the file domain_ips.txt. |
| --subfile \<file> | Write all valid subdomains to this file. |
| -t<br>--timeout \<value> | The tcp and udp timeout values in seconds (default: 10s). |
| --threads \<value> | The number of threads that will perform different queries. |
| -v<br>--verbose | Be verbose: show all the progress and all the error messages. |
|  | &nbsp;&nbsp;&nbsp;&nbsp;GOOGLE SCRAPING OPTIONS: |
| -p<br>--pages \<value> | The number of google search pages to process when scraping names, the default is 5 pages, the -s switch must be specified. |
| -s<br>--scrap \<value> | The maximum number of subdomains that will be scraped from Google (default 15). |
|  | &nbsp;&nbsp;&nbsp;&nbsp;BRUTE FORCE OPTIONS: |
| -f<br>--file \<file> | Read subdomains from this file to perform brute force. (Takes priority over default dns.txt) |
| -u<br>--update	\<a\|g\|r\|z> | Update the file specified with the -f switch with valid subdomains. |
| &nbsp;&nbsp;&nbsp;&nbsp;a | Update using all results. |
| &nbsp;&nbsp;&nbsp;&nbsp;g | Update using only google scraping results. |
| &nbsp;&nbsp;&nbsp;&nbsp;r | Update using only reverse lookup results. |
| &nbsp;&nbsp;&nbsp;&nbsp;z | Update using only zonetransfer results. |
| -r<br>--recursion | Recursion on subdomains, brute force all discovered subdomains that have an NS record. |
|  | &nbsp;&nbsp;&nbsp;&nbsp;WHOIS NETRANGE OPTIONS: |
| -d,<br> --delay \<value> | The maximum value of seconds to wait between whois queries, the value is defined randomly, default: 3s. |
| -w<br>--whois | Perform the whois queries on c class network ranges.<br>**Warning**: this can generate very large netranges and it will take lot of time to perform reverse lookups. |
|  | REVERSE LOOKUP OPTIONS: |
| -e<br>--exclude	\<regexp> | Exclude PTR records that match the regexp expression from reverse lookup results, useful on invalid hostnames. |
|  | &nbsp;&nbsp;&nbsp;&nbsp;OUTPUT OPTIONS: |
| -o<br>--output \<file> | Output in XML format. Can be imported in MagicTree (www.gremwell.com) |

### nslookup - Windows

Usage
```powershell
nslookup [exit | finger | help | ls | lserver | root | server | set | view] [options]
```

| Options | Desc |
| ---- | ---- |
| exit | Exits the nslookup command-line tool. |
| finger | Connects with the finger server on the current computer. |
| help | Displays a short summary of subcommands. |
| ls | Lists information for a DNS domain. |
| lserver | Changes the default server to the specified DNS domain. |
| root | Changes the default server to the server for the root of the DNS domain name space. |
| server | Changes the default server to the specified DNS domain. |
| set | Changes configuration settings that affect how lookups function. |
| set all | Prints the current values of the configuration settings. |
| set class | Changes the query class. The class specifies the protocol group of the information. |
| set d2 | Turns exhaustive Debugging mode on or off. All fields of every packet are printed. |
| set debug | Turns Debugging mode on or off |
| set domain | Changes the default DNS domain name to the name specified. |
| set port | Changes the default TCP/UDP DNS name server port to the value specified. |
| set querytype | Changes the resource record type for the query. |
| set recurse | Tells the DNS name server to query other servers if it doesn't have the information. |
| set retry | Sets the number of retries. |
| set root | Changes the name of the root server used for queries. |
| set search | Appends the DNS domain names in the DNS domain search list to the request until an answer is received. This applies when the set and the lookup request contain at least one period, but do not end with a trailing period. |
| set srchlist | Changes the default DNS domain name and search list. |
| set timeout | Changes the initial number of seconds to wait for a reply to a request. |
| set type | Changes the resource record type for the query. |
| set vc | Specifies to use or not use a virtual circuit when sending requests to the server. |
| view | Sorts and lists the output of the previous **ls** subcommand or commands. |


### Removed from course:
#### dig

Usage:
```bash
dig <type> <domain> <addt options>
```

|       Options       | Desc                                                                                    |
|:-------------------:| --------------------------------------------------------------------------------------- |
|       **-b**        | Specify source IP address                                                               |
|       **-m**        | Enable memory usage debugging                                                           |
|       **-p**        | Send query to non-standard port                                                         |
|       **-q**        | Domain name to query (useful when needing to distinguish from other arguments)          |
|       **-v**        | Print version number and exit                                                           |
|    **-x** _addr_    | Use Reverse Lookup on given IP _addr_                                                   |
|       **ANY**       | Queries all available record types                                                      |
|  **+\[no\]stats**   | Toggles printing of statistics                                                          |
|   **+\[no\]cmd**    | Toggles initial comment (ID'ing the version of dig and the query options) in the output |
| **+\[no\]comments** | Toggles display of some comment lines (packet header, etc) in the output                |
| **+\[no\]answer**                    | Control display of answer section                                     |

#### Sublist3r

Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT.
[https://github.com/aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r)

| Options | Desc |
| ---- | ---- |
| -d<br>--domain | Domain name to enumerate subdomains of |
| -b<br>--bruteforce | Enable the subbrute bruteforce module |
| -p<br>--ports | Scan the found subdomains against specific tcp ports |
| -v<br>--verbose | Enable the verbose mode and display results in realtime |
| -t<br>--threads | Number of threads to use for subbrute bruteforce |
| -e<br>--engines | Specify a comma-separated list of search engines |
| -o<br>--output | Save the results to text file |
| -h<br><br>--help | show the help message and exit |



## Port Scanning

### netcat
Utility which reads and writes data across network connections, using TCP or UDP protocols.  
  
Server mode: Has the listener on it  
Client mode: ‘Dials’ into the server.  
  
We can use client mode to connect to any TCP/UDP port, allowing us to:
- Check if a port is open or closed.  
- Read a banner from the service listening on a port.  
- Connect to a network service manually.

| Options               | Desc                                                                                                                                                                                                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -e                    | Executes a command after making or receiving a successful connection.<br>Not available on most modern Linux/BSD systems<br>Included w/ Kali<br>When enabled, can redirect the input, output, and error messages of an executable to a TCP/UDP port (ex: bind shell) |
| -l                    | Create a listener                                                                                                                                                                                                                                                   |
| -C                    | Send CarriageReturn LineFeed (usefull when connecting via SMTP)                                                                                                                                                                                                     |
| -n                    | Skip DNS name resolution                                                                                                                                                                                                                                            |
| -p                    | Specify port number                                                                                                                                                                                                                                                 |
| -u                    | UDP mode                                                                                                                                                                                                                                                            |
| -v                    | Verbose mode                                                                                                                                                                                                                                                        |
| -w                    | Specify connection timeout in seconds                                                                                                                                                                                                                               |
| -z                    | Specifies zero-I/O mode. Used for scanning and sends no data.                                                                                                                                                                                                       |
|                       |                                                                                                                                                                                                                                                                     |
| nc -l _port_ > _file_ | Redirect output to _file_                                                                                                                                                                                                                                           |
| nc < _file_           | Pushes _file_                                                                                                                                                                                                                                                       |

### nmap

Port scanner and vuln finder.
Best to use _**sudo**_ when running **nmap** as many scanning options require access to raw sockets - which requires root privileges.

Usage:
```bash
nmap [Options] [IP]
```


###### Target & Port Specifications:

| Options                | Desc                                                               |
| ---------------------- | ------------------------------------------------------------------------------------------- |
| **-p**                 | Specify port or port range                                                                  |
| **-p-**                | Scan all ports                                                                              |
| **--top-ports** <_x_>  | Scans for given number _x_ of top ports (determined within _/usr/share/nmap/nmap-services_) |
| **-iL** _\<filename\>_ | Scan targets from a file                                                                    |

###### Scan Techniques:

| Options                   | Desc                                                                                                                                                                                                                                                                                                                                     |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **-sS**                   | SYN scan/ “stealth” scan. Sends SYN packets to port w/o completing 3-way. Default scan when no other scan type is specified & with root privilege.<br>Faster and more efficient. Also, as the handshake doesn't complete, info is not passed to the Application layer and will not appear on logs (however, may appear in Firewall logs) |
| **-sT**                   | Connect scan. Completes 3-way handshake. Default scan w/o root privilege.<br>Takes longer than SYN scan, but doesn't require elevated privileges as it uses Berkeley sockets API.                                                                                                                                                        |
| **-sU**                   | UDP scan                                                                                                                                                                                                                                                                                                                                 |
| **-sA**                   | ACK scan - helpful w/ figuring out firewalls rule sets and config                                                                                                                                                                                                                                                                        |
| **-sW**                   | Window scan - Exactly like ACK scan, only examines TCP Window field of the RST packets returned                                                                                                                                                                                                                                          |
| **-sN**/ **-sF**/ **-sX** | TCP Null (doesn't set any bits/ TCP flag header is 0), FIN (just sets FIN bit), and XMAS scans<br>(sets FIN, PSH, & URG flags -lighting the packet up like a christmas tree)                                                                                                                                                                |
| **--scanflags**           | Allows customization on which TCP flags are set                                                                                                                                                                                                                                                                                          |
  
###### Host Discovery:

| Options                                                                         | Desc                                                                                             |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| **-sL**          | List scan. Lists targets to scan within block of IP addresses                                                                                                 |
| **-sn**                                                                         | Ping scan. Disables port scan.                                                                   |
| **-Pn**                                                                         | Skip host discovery - pinging host before scanning. (Windows by default blocks ICMP echo replys) |
| **-PS**                                                                         | SYN discovery on given port. Default: 80                                                         |
| **-PA**                                                                         | ACK discovery on given port. Default: 80                                                         |
| **-PU**                                                                         | UDP discovery on given port. Default: 80                                                         |
| **-PR**                                                                         | ARP discovery on a local network                                                                 |
| **-PE**                                                                         | ICMP Echo Requests                                                                               |
| **-PM**                                                                         | ICMP Address Mask Requests                                                                       |
| **-PP**                                                                         | ICMP Timestamp Requests                                                                          |
| **-n** / **-R** | Never do DNS resolution/ Always resolve \[default: sometimes\]                                                                                                 |
  
###### Service, Version, and OS Detection:  

| Options                                       | Desc                                                                                                                             |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **-A**                                        | Aggressive scanning. Enables OS detection, version detection, script scanning, and traceroute                                    |
| **-O**                                        | Enable OS detection using TCP/IP stack fingerprinting                                                                            |
| **-sV**                                       | Probe banners to determine service/ version info                                                                                 |
| **--version-intensity** <_x_/ _light_/ _all_> | Intenity level 0-9. Higher number increases possibility of correctness/ Enables light mode - faster, less correct/ Sets lvl to 9 |

###### Timing and Performance:

| Options   | Desc                                                                       |
| --------- | -------------------------------------------------------------------------- |
| **-F**    | Enable fast mode. Decreases number of scanned ports to 100 most common     |
| **-r**    | Scans ports in consecutive order rather than random                        |
| **-T**_#_ | Set speed of scan                                                          |
| **0**     | Paranoid. IDS evasion                                                      |
| **1**     | Sneaky. IDS evasion                                                        |
| **2**     | Polite. Slows scan to use less bandwidth and less target machine resources |
| **3**     | Normal. Default speed                                                      |
| **4**     | Aggressive. Assumes you're on a fast and reliable network                  |
| **5**     | Insane. Assumes an extraordinarily fast network                            |

###### Firewall/ IDS Evasion and Spoofing:

| Options                        | Desc                                                                                                                                             |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **-D** _\<decoy-ip-list\>_     | Send scans from spoofed IPs                                                                                                                      |
| **-f**                         | Used to fragment the packets (i.e. split them into smaller pieces) making it less likely that the packets will be detected by a firewall or IDS  |
| **-g** _\<port\>_              | Use given source port number                                                                                                                     |
| **-S**                         | Designate spoofed-IP                                                                                                                             |
| **--spoof-mac**                | Designate spoofed-mac address                                                                                                                    |
| **-sI**                        | Idle/ zombie scan. Requires idle system on network and pushes scans through its IP.                                                              |
| **--badsum**                   | Generate in invalid checksum for packets. Can be used to determine the presence of a firewall/IDS.                                               |
| **--data-length** _\<length\>_ | Appends random data to sent packets                                                                                                              |
| **--mtu** _\<number\>_         | Similar to **-f**, but allows specifying size of packet. This _must_ be a multiple of 8.                                                         |
| **--scan-delay** _\<time\>_    | Adds a delay between packets sent. Useful if the network is unstable and for evading any time-based firewall/IDS triggers which may be in place. |
```bash
nmap -e NET_INTERFACE -Pn -S SPOOFED_IP 10.10.232.227
```
	*Note: Need to specify interface & disable Ping Scan:

  
###### NSE Scripts:

| Options                             | Desc                                                                                                                                                             |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **-sC**                             | Default scripts. Considered useful for discovery and safe                                                                                                        |
| **--script=**_<script/ */ ,script>_ | Scan with specified script/s. Can use single script. Can use wildcard for all scripts w/ of a kind (Ex: http*)<br>Can scan with multiple scripts comma separated |
| **--script-args**                   | Specifies arguments of previously specified **--script=**_script_                                                                                                |

###### Output:  

| Options | Desc |
| ---- | ---- |
| **-oG** | Output results in **grep**-able format |
| **-oG -** | Grepable output to the screen. |
| **-oX** | Outputs to XML |
| **-oA** | Output all formats |
| **-oN** | Requests normal output be given to the file name |
| **--apend-output** | Appends a scan to a previous scan file |
| **-v**/ **-vv** | Increase verbosity level (Displays results as they come) |
| **-d**/ **-dd** | Increase debugging level |
| **--open** | Only return matches with open ports |
```bash
nmap -p80 -sV -oG - --open 192.168.1.1/24 | grep open
```
	Scan for web servers and grep to show which IPs are running them  
  
  
###### Etc:  

| Options           | Desc                        |
| ----------------- | --------------------------- |
| **--dns-servers** | Specify custom DNS servers  |
| **--system-dns**  | Use OS's DNS resolver       |
| **--traceroute**  | Trace hop path to each host |
  
###### States:  

| Reply                | Indication                                                                                                                                                                                                                                                                                           |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Open**             | A service is listening on the specified port.                                                                                                                                                                                                                                                        |
| **Closed**           | No service is listening on the specified port, although the port is accessible.<br>By accessible, we mean that it is reachable and is not blocked by a firewall or other security appliances/programs.                                                                                               |
| **Filtered**         | Cannot determine if the port is open or closed because the port is not accessible.<br>This state is usually due to a firewall preventing Nmap from reaching that port. <br>Nmap’s packets may be blocked from reaching the port; alternatively, the responses are blocked from reaching Nmap’s host. |
| **Unfiltered**       | Cannot determine if the port is open or closed, although the port is accessible.<br>This state is encountered when using an ACK scan -sA.                                                                                                                                                            |
| **Open / Filtered**   | Cannot determine whether the port is open or filtered.                                                                                                                                                                                                                                               |
| **Closed / Filtered** | Cannot decide whether a port is closed or filtered.                                                                                                                                                                                                                                                  |

### iptables
### Removed from course