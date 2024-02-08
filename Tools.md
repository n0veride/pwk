
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

Usage:
```bash
recon-ng [-h] [-w workspace] [-r filename] [--no-version] [--no-analytics] [--no-marketplace] [--stealth] [--accessible] [--version]
```

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
  
Can import [nmap](Tools.md#nmap) (& other tools) to ingest its output into recon-ng's database. Allows you to keep the work done w/in Nmap

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

Port scanner, vuln finder, enumerator.
Best to use _**sudo**_ when running **nmap** as many scanning options require access to raw sockets - which requires root privileges.
NSE scripts are located _/usr/share/nmap/scripts_ & can be searched through the index called _script.db_

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

  
###### NSE Scripts
Nmap Scripting Engine.  
  
Used to launch user-created scripts that help automate scanning and enumeration tasks.  
  
Scripts are written in Lua and range in functionality from brute force and authentication to detecting and exploiting vulnerabilities.  
Located _/usr/share/nmap/scripts_ with an index called _script.db_ 

| Options | Desc |
| ---- | ---- |
| **-sC** | Default scripts. Considered useful for discovery and safe |
| **--script=**_<script/ */ ,script>_ | Scan with specified script/s. Can use single script. Can use wildcard for all scripts w/ of a kind (Ex: http*)<br>Can scan with multiple scripts comma separated |
| **--script-args** | Specifies arguments of previously specified **--script=**_script_ |
| --script-help _<script_> | Displays description of script and URL for more info |

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
nmap -p80 -sV -oG --open 192.168.5.140/24 \| grep open
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

### Removed from course
#### masscan

Fastest port scanner - created to scan the “entire internet” within 6 minutes.  Great for scanning Class A and B subnets.  
Implements custom TCP/ IP stack and requries **sudo**'s access to raw sockets. 

Usage:
```bash
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
```

| Options         | Desc                                              |
| --------------- | ------------------------------------------------- |
| **-p**          | - Specifies port                                  |
| **--rate**      | Specifies desired rate of packet transmission     |
| **-e**          | Specifies raw network interface to use (Ex: tap0) |
| **--router-ip** | Specifies IP address for the appropriate gateway  |


## SMB Enumeration

### nbtscan

Scans IP networks for NetBIOS name information.

Usage:
```bash
nbtscan [-v] [-d] [-e] [-l] [-t timeout] [-b bandwidth] [-r] [-q] [-s separator] [-m retransmits] (-f filename)|(<scan_range>)
```

| Options        | Desc                                                                                                                                              |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| -v             | Verbose output. Print all names received from each host                                                                                           |
| -d             | Dump packets. Print whole packet contents.                                                                                                        |
| -e             | Format output in /etc/hosts format.                                                                                                               |
| -l             | Format output in lmhosts format. Cannot be used with -v, -s or -h options.                                                                        |
| -t timeout     | Wait timeout milliseconds for response.Default 1000.                                                                                              |
| -b bandwidth   | Output throttling. Slow down output so that it uses no more that bandwidth bps. Useful on slow links, so that outgoing queries don't get dropped. |
| -r             | Use local port 137 for scans. Win95 boxes respond to this only. You need to be root to use this option on Unix.                                   |
| -q             | Suppress banners and error messages,                                                                                                              |
| -s separator   | Script-friendly output. Don't print column and record headers, separate fields with separator.                                                    |
| -h             | Print human-readable names for services. Can only be used with -v option.                                                                         |
| -m retransmits | Number of retransmits. Default 0.                                                                                                                 |
| -f filename    | Take IP addresses to scan from file filename.<br> -f - makes nbtscan take IP addresses from stdin. xxx.xxx.xxx.xxx\/xx or xxx.xxx.xxx.xxx-xxx.    |


### Removed from course:

#### enum4linux

Tool for enumerating information from Windows and Samba systems.  
Written in PERL and is basically a wrapper around the Samba tools **smbclient**, **rpclient**, **net**, and **nmblookup**

Usage
```bash
enum4linux -U -o 192.168.1.200
```

| Options           | Desc                                                          |
| ----------------- | ------------------------------------------------------------- |
| **-a**            | Do all simple enumeration (-U -S -G -P -r -o -n -i). Default  |
| **-U**            | Get userlist                                                  |
| **-M**            | Get machine list*                                             |
| **-S**            | Get sharelist                                                 |
| **-P**            | Get password policy information                               |
| **-G**            | Get group and member list                                     |
| **-d**            | Be detailed, applies to -U and -S                             |
| **-u** _\<user\>_ | Specify username to use (default "")                          |
| **-p** _\<pass\>_ | Specify password to use (default "")                          |
| **-v**            | Verbose. Shows full commands being run (net, rpcclient, etc.) |
| **-o**            | Get OS information                                            |
| **-i**            | Get printer information                                       |
  
The following options from enum.exe aren't implemented: -L, -N, -D, -f

| Addt Options               | Desc                                                                                                                                                                                                                   |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **-r**                | Enumerate users via RID cycling                                                                                                                                                                                        |
| **-R** _\<range\>_    | RID ranges to enumerate (default: 500-550,1000-1050, implies -r)                                                                                                                                                       |
| **-K** _\<n\>_        | Keep searching RIDs until _n_ consective RIDs don't correspond to a username. Impies RID range ends at 999999. Useful against DCs.                                                                                     |
| **-l**                | Get some (limited) info via LDAP 389/TCP (for DCs only)                                                                                                                                                                |
| **-s** _\<filename\>_ | Brute force guessing for share names                                                                                                                                                                                   |
| **-k** _\<user\>_     | User(s) that exists on remote system (default: administrator,guest,krbtgt,domain admins,root,bin,none).<br>Used to get sid with "lookupsid known_username" <br>Use commas to try several users: "-k admin,user1,user2" |
| **-w** _\<wrkg\>_     | Specify workgroup manually (usually found automatically)                                                                                                                                                               |
| **-n**                | Do an nmblookup (similar to nbtstat)                                                                                                                                                                                   |

#### smbclient

Ftp-like client to access SMB/CIFS rshares on servers

Usage:
```bash
smbclient [OPTIONS] service <password>
```

| sec504 Options | Desc |
| ---- | ---- |
| **-L** | Lists shares of the target system |
| **-U** | Specifies username |
| **%** | Allows typing of plaintext password directly after user when trying to connect. (ex: <user>%<pw>) |
| **allinfo** | Used to ID Alternate Data Streams |
| \*\***get** | Download file |
| \*\***tar** | Can use tar cmd to compress directories for download (ex: tar c <\folder>.tar *) |
| **-m \<SMB2>** | Forces use of specific SMB protocol |
	\*\* Once Connected

| Options                                 | Desc                                             |
| --------------------------------------- | ------------------------------------------------ |
| -M, --message=HOST                      | Send message                                     |
| -I, --ip-address=IP                     | Use this IP to connect to                        |
| -E, --stderr                            | Write messages to stderr instead of stdout       |
| -L, --list=HOST                         | Get a list of shares available on a host         |
| -T, --tar=<c\|x>\IXFvgbNan              | Command line tar                                 |
| -D, --directory=DIR                     | Start from directory                             |
| -c, --command=STRING                    | Execute semicolon separated commands             |
| -b, --send-buffer=BYTES                 | Changes the transmit/send buffer                 |
| -t, --timeout=SECONDS                   | Changes the per-operation timeout                |
| -p, --port=PORT                         | Port to connect to                               |
| -g, --grepable                          | Produce grepable output                          |
| -q, --quiet                             | Suppress help message                            |
| -B, --browse                            | Browse SMB servers using DNS                     |
|                                         |                                                  |
| Help options:                           |                                                  |
| -?, --help                              | Show this help message                           |
| --usage                                 | Display brief usage message                      |
|                                         |                                                  |
| Common Samba options:                   |                                                  |
| -d, --debuglevel=DEBUGLEVEL             | Set debug level                                  |
| --debug-stdout                          | Send debug output to standard output             |
| -s, --configfile=CONFIGFILE             | Use alternative configuration file               |
| --option=name=value                     | Set smb.conf option from command line            |
| -l, --log-basename=LOGFILEBASE          | Basename for log/debug files                     |
| --leak-report                           | Enable talloc leak reporting on exit             |
| --leak-report-full                      | Enable full talloc leak reporting on exit        |
|                                         |                                                  |
| Connection options:                     |                                                  |
| -R, --name-resolve=NAME-RESOLVE-ORDER   | Use these name resolution services only          |
| -O, --socket-options=SOCKETOPTIONS      | Socket options to use                            |
| -m, --max-protocol=MAXPROTOCOL          | Set max protocol level                           |
| -n, --netbiosname=NETBIOSNAME           | Primary netbios name                             |
| --netbios-scope=SCOPE                   | Use this Netbios scope                           |
| -W, --workgroup=WORKGROUP               | Set the workgroup name                           |
| --realm=REALM                           | Set the realm name                               |
|                                         |                                                  |
| Credential options:                     |                                                  |
| -U, --user=[DOMAIN/]USERNAME[%PASSWORD] | Set the network username                         |
| -N, --no-pass                           | Don't ask for a password                         |
| --password=STRING                       | Password                                         |
| --pw-nt-hash                            | The supplied password is the NT hash             |
| -A, --authentication-file=FILE          | Get the credentials from a file                  |
| -P, --machine-pass                      | Use stored machine account password              |
| --simple-bind-dn=DN                     | DN to use for a simple bind                      |
| --use-kerberos=desired\|required\|off   | Use Kerberos authentication                      |
| --use-krb5-ccache=CCACHE                | Credentials cache location for Kerberos          |
| --use-winbind-ccache                    | Use the winbind ccache for authentication        |
| --client-protection=sign\|encrypt\|off  | Configure used protection for client connections |
|                                         |                                                  |
| Deprecated legacy options:              |                                                  |
| -k, --kerberos                          | DEPRECATED: Migrate to --use-kerberos            |
|                                         |                                                  |
| Version options:                        |                                                  |
| -V, --version                           | Print version                                    |

#### rpcclient

Tool for executing client side MS-RPC functions

Usage:
```bash
rpcclient [OPTION...] BINDING-STRING|HOST
```

Connect w/ user:
```bash
rpcclient 10.10.0.1 -U sec504
```

| sec 504 Options                | Desc                                                                      |
| ---------------------- | --------------------------------------------------------------------- |
| **enumdomusers**       | List users                                                            |
| **srvinfo**            | Show OS type and version                                              |
| **enumalsgroups**      | (Followed by word domain or builtin) - List groups (enum alias group) |
| **lsaenumsid**         | Show all users SIDs defined on the box                                |
| **lookupnames \<name>** | Show SID associated w/ user or group name                             |
| **lookupsids \<sid>**   | Show username associated w/ SID                                       |

| Options | Desc |
| ---- | ---- |
| -c, --command=COMMANDS | Execute semicolon separated cmds |
| -I, --dest-ip=IP | Specify destination IP address |
| -p, --port=PORT | Specify port number |
|  | Help options: |
| -?, --help | Show this help message |
| --usage | Display brief usage message |
|  |  |
| Common Samba options: |  |
| -d, --debuglevel=DEBUGLEVEL | Set debug level |
| --debug-stdout | Send debug output to standard output |
| -s, --configfile=CONFIGFILE | Use alternative configuration file |
| --option=name=value | Set smb.conf option from command line |
| -l, --log-basename=LOGFILEBASE | Basename for log/debug files |
| --leak-report | enable talloc leak reporting on  exit |
| --leak-report-full | enable full talloc leak reporting on exit |
|  |  |
| Connection options: |  |
| -R, --name-resolve=NAME-RESOLVE-ORDER | Use these name resolution services only |
| -O, --socket-options=SOCKETOPTIONS | socket options to use |
| -m, --max-protocol=MAXPROTOCOL | Set max protocol level |
| -n, --netbiosname=NETBIOSNAME | Primary netbios name |
| --netbios-scope=SCOPE | Use this Netbios scope |
| -W, --workgroup=WORKGROUP | Set the workgroup name |
| --realm=REALM | Set the realm name |
|  |  |
| Credential options: |  |
| -U, --user=\[DOMAIN/]USERNAME\[%PASSWORD] | Set the network username |
| -N, --no-pass | Don't ask for a password |
| --password=STRING | Password |
| --pw-nt-hash | The supplied password is the NT hash |
| -A, --authentication-file=FILE | Get the credentials from a file |
| -P, --machine-pass | Use stored machine account password |
| --simple-bind-dn=DN | DN to use for a simple bind |
| --use-kerberos=desired\|required\|off | Use Kerberos authentication |
| --use-krb5-ccache=CCACHE | Credentials cache location for Kerberos |
| --use-winbind-ccache | Use the winbind ccache for authentication |
| --client-protection=sign\|encrypt\|off | Configure used protection for client connections |
|  |  |
| Deprecated legacy options: |  |
| -k, --kerberos | DEPRECATED: Migrate to --use-kerberos |
|  |  |
| Version options: |  |
| -V, --version | Print version |

## SMTP Enumeration

### nmap enumeration:
```bash
sudo nmap -p 25 --script=smtp-enum* <target DOMAIN/ip>
```

### Connect through nc:
```bash
nc -nv <IP> 25
```

### Connect through telnet - Windows:
```powershell
telnet <IP>
```

### SMTP

| Command                     | Desc                                                                     | Required           |
| --------------------------- | ------------------------------------------------------------------------ | ------------------ |
| HELO \<domain>              | Provides the identification of the sender i.e. the host name             | Mandatory          |
| MAIL FROM : \<reverse-path> | Specifies the originator of the mail.                                    | Mandatory          |
| RCPT TO : \<forward-path>   | Specifies the recipient of mail.                                         | Mandatory          |
| DATA                        | Specifies the beginning of the mail.                                     | Mandatory          |
| QUIT                        | Closes the TCP connection.                                               | Mandatory          |
| RSET                        | Aborts the current mail transaction but the TCP connection remains open. | Highly recommended |
| VRFY \<user>                | Confirm or verify the user name.                                         | Highly recommended |
| NOOP                        | No operation                                                             | Highly recommended |
| TURN                        | Reverses the role of sender and receiver.                                | Seldom used        |
| EXPN \<mailing list>        | Specifies the mailing list to be expanded.                               | Seldom used        |
| HELP \<string>              | Send some specific documentation to the system.                          | Seldom used        |
| SEND FROM : \<reverse-path> | Send mail to the terminal.                                               | Seldom used        |
| SOML FROM : \<reverse-path> | Send mail to the terminal if possible; otherwise to mailbox.             | Seldom used        |
| SAML FROM : \<reverse-path> | Send mail to the terminal and mailbox.                                   | Seldom used        |


## SNMP

### onesixtyone

Usages:
```bash
onesixtyone 192.168.4.0/24 public
onesixtyone -c dict.txt -i hosts -o my.log -w 100
```

| Option              | Desc                                                                                                                                                            |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -c \<communityfile> | File with community names to try                                                                                                                                |
| -i \<inputfile>     | File with target hosts                                                                                                                                          |
| -o \<outputfile>    | Output log                                                                                                                                                      |
| -p                  | Specify an alternate destination SNMP port                                                                                                                      |
| -d                  | Debug mode, use twice for more information                                                                                                                      |
| -s                  | Short mode, only print IP addresses                                                                                                                             |
| -w n                | Wait n milliseconds (1/1000 of a second) between sending packets (default 10)                                                                                   |
| -q                  | Quiet mode, do not print log to stdout, use with -o  |
	host is either an IPv4 address or an IPv4 address and a netmask default community names are: public private


### snmpwalk

Uses SNMP GETNEXT requests to probe and query a network entity for tree values. Need to know the read-only community string (most cases “public”)  
  
An OID (object identifier) may be given on the cmd line specifying which portion of the OID space will be searched. 

Usage:
```bash
snmpwalk [App Options] [Common Options] [OID]
```

| Options | Desc |
| ---- | ---- |
| -h, --help | Display this help message |
| -H | Display configuration file directives understood |
| -v 1\|2c\|3 | Specifies SNMP version to use |
| -V, --version | Display package version number |
|  |  |
| **SNMP Version 1 or 2c specific** |  |
| -c COMMUNITY | Set the community string |
|  |  |
| **SNMP Version 3 specific** |  |
| -a PROTOCOL | Set authentication protocol (MD5\|SHA\|SHA-224\|SHA-256\|SHA-384\|SHA-512) |
| -A PASSPHRASE | Set authentication protocol pass phrase |
| -e ENGINE-ID | Set security engine ID (e.g. 800000020109840301) |
| -E ENGINE-ID | Set context engine ID (e.g. 800000020109840301) |
| -l LEVEL | Set security level (noAuthNoPriv\|authNoPriv\|authPriv) |
| -n CONTEXT | Set context name (e.g. bridge1) |
| -u USER-NAME | Set security name (e.g. bert) |
| -x PROTOCOL | Set privacy protocol (DES\AES\|\AES-192\|AES-256) |
| -X PASSPHRASE | Set privacy protocol pass phrase |
| -Z BOOTS,TIME | Set destination engine boots/time |
|  | **General communication options** |
| -r RETRIES | Set the number of retries |
| -t TIMEOUT | Set the request timeout (in seconds) |
| Debugging |  |
| -d | Dump input/output packets in hexadecimal |
| -D\[TOKEN\[,...]] | Turn on debugging output for the specified TOKENs<br>(ALL gives extremely verbose debugging output) |
| General options |  |
| -m MIB\[:...] | Load given list of MIBs (ALL loads everything) |
| -M DIR\[:...] | Look in given list of directories for MIBs<br>(default: $HOME\/.snmp\/mibs:\/usr\/share\/snmp\/mibs:\/usr\/share\/snmp\/mibs\/iana:\/usr\/share\/snmp\/mibs\/ietf) |
|  |  |
| -P MIBOPTS | Toggle various defaults controlling MIB parsing: |
|  | u:  allow the use of underlines in MIB symbols |
|  | c:  disallow the use of "--" to terminate comments |
|  | d:  save the DESCRIPTIONs of the MIB objects |
|  | e:  disable errors when MIB symbols conflict |
|  | w:  enable warnings when MIB symbols conflict |
|  | W:  enable detailed warnings when MIB symbols conflict |
|  | R:  replace MIB symbols from latest module |
|  |  |
| -O OUTOPTS | Toggle various defaults controlling output display: |
|  | 0:  print leading 0 for single-digit hex characters |
|  | a:  print all strings in ascii format |
|  | b:  do not break OID indexes down |
|  | e:  print enums numerically |
|  | E:  escape quotes in string indices |
|  | f:  print full OIDs on output |
|  | n:  print OIDs numerically |
|  | p PRECISION:  display floating point values with specified PRECISION (printf format string) |
|  | q:  quick print for easier parsing |
|  | Q:  quick print with equal-signs |
|  | s:  print only last symbolic element of OID |
|  | S:  print MIB module-id plus last element |
|  | t:  print timeticks unparsed as numeric integers |
|  | T:  print human-readable text along with hex strings |
|  | u:  print OIDs using UCD-style prefix suppression |
|  | U:  don't print units |
|  | v:  print values only (not OID = value) |
|  | x:  print all strings in hex format |
|  | X:  extended index format |
|  |  |
| -I INOPTS | Toggle various defaults controlling input parsing: |
|  | b:  do best/regex matching to find a MIB node |
|  | h:  don't apply DISPLAY-HINTs |
|  | r:  do not check values for range/type legality |
|  | R:  do random access to OID labels |
|  | u:  top-level OIDs must have '.' prefix (UCD-style) |
|  | s SUFFIX:  Append all textual OIDs with SUFFIX before parsing |
|  | S PREFIX:  Prepend all textual OIDs with PREFIX before parsing |
|  |  |
| -L LOGOPTS | Toggle various defaults controlling logging: |
|  | e:           log to standard error |
|  | o:           log to standard output |
|  | n:           don't log at all |
|  | f file:      log to the specified file |
|  | s facility:  log to syslog (via the specified facility) |
|  |  |
|  | (variants) |
|  | \[EON] pri:   log to standard error, output or /dev/null for level 'pri' and above |
|  | \[EON] p1-p2: log to standard error, output or /dev/null for levels 'p1' to 'p2' |
|  | \[FS] pri token:    log to file/syslog for level 'pri' and above |
|  | \[FS] p1-p2 token:  log to file/syslog for levels 'p1' to 'p2' |
|  |  |
| -C APPOPTS | Set various application specific behaviours: |
|  | p:  print the number of variables found |
|  | i:  include given OID in the search range |
|  | I:  don't include the given OID, even if no results are returned |
|  | c:  do not check returned OIDs are increasing |
|  | t:  Display wall-clock time to complete the walk |
|  | T:  Display wall-clock time to complete each request |
|  | E {OID}:  End the walk at the specified OID |

### Removed from course:

#### snmpcheck

Check hosts SNMP access
	Couldn't get to work

Usage:
```bash
snmpcheck [-x] [-n|y] [-h] [-H] [-V NUM] [-L] [-f] [[-a] HOSTS] 
```

| Options | Desc |  |
| ---- | ---- | ---- |
| -h | Display this message. |  |
| -a | Check error log file AND hosts specified on command line. |  |
| -p | Don't try and ping-echo the host first |  |
| -f | Only check for things I can fix |  |
|  | HOSTS	check these hosts for problems. |  |
| X Options: |  |  |
| -x | Forces ascii base if $DISPLAY set (instead of tk). |  |
| -H | Start in hidden mode.  (hides user interface) |  |
| -V NUM | Sets the initial verbosity level of the command log (def: 1) |  |
| -L | Show the log window at startup |  |
| -d | Don't start by checking anything.  Just bring up the interface. |  |
|  |  |  |
|  | Ascii Options: |  |
| -n | Don't ever try and fix the problems found.  Just list. |  |
| -y | Always fix problems found. |  |

## NFS Enumeration - Removed

# Vulnerability Scanning

## Nessus

[https://www.tenable.com/downloads/nessus](https://www.tenable.com/downloads/nessus)  

Some supported scan types:  
• Basic Network Scan: Generic scan with various checks that are suitable to be used against various target types.  
• Credentialed Patch Audit: Authenticated scan that enumerates missing patches.  
• Web Application Tests: Specialized scan for discovering published vulnerabilities in Web Applications.  
• Spectre and Meltdown: Targeted scan for the _Spectre_ and _Meltdown_ vulnerabilities.  

By default, the Basic Network Scan will only scan the common ports.  
To change this, we click the Discovery link on the left side of the Settings tab.

# Web App

## Fingerprinting and Enumeration

### nmap:

##### Banner grabbing:
```bash
sudo nmap -sV -p 80 <ip>
```

##### Service specific enumeration:
```bash
sudo nmap -p 80 --script=http-enum <ip>
```


### Wappalizer

Browser plugin which can retrieve information on the technology stack used by a site.  Firefox and Chrome compatible.

### GoBuster

Directory, file, and DNS "busting" tool written in Go
	\*Generates a lot of traffic, so not best tool for stealth.
	\*\*Can reduce number of threads used (Default 10) with the **-t** switch.

Usage:
```bash
gobuster -e -u http://192.168.0.155/ -w /usr/share/wordlists/dirb/common.txt
```

| Available Commands         | Desc                                                                                                |
| --------------------------- | ----------------------------------------------------------------------------------------------- |
| completion                  | Generate the autocompletion script for the specified shell                                      |
| dir                         | Uses directory/ file enumeration mode                                                            |
| dns                         | Uses DNS subdomain enumeration mode                                                             |
| fuzz                        | Uses fuzzing mode. Replaces the keyword FUZZ in the URL, Headers and the request body           |
| gcs                         | Uses gcs bucket enumeration mode                                                                |
| help                        | Help about any command                                                                          |
| s3                          | Uses aws bucket enumeration mode                                                                |
| tftp                        | Uses TFTP enumeration mode                                                                      |
| version                     | shows the current version                                                                       |
| vhost                       | Uses VHOST enumeration mode (you most probably want to use the IP address as the URL parameter) |
|                             |                                                                                                 |
| Options                     | Desc                                                                                            |
| --debug                     | Enable debug output                                                                             |
| --delay duration            | Time each thread waits between requests (e.g. 1500ms)                                           |
| -h<br>--help                | help for gobuster                                                                               |
| --no-color                  | Disable color output                                                                            |
| --no-error                  | Don't display errors                                                                            |
| -z<br>--no-progress         | Don't display progress                                                                          |
| -o<br>--output string       | Output file to write results to (defaults to stdout)                                            |
| -p<br>--pattern string      | File containing replacement patterns                                                            |
| -q<br>--quiet               | Don't print the banner and other noise                                                          |
| -t<br>--threads \<int>      | Number of concurrent threads (default 10)                                                       |
| -v<br>--verbose             | Verbose output (errors)                                                                         |
| -w<br>--wordlist \<string>  | Path to the wordlist. Set to - to use STDIN.                                                    |
| --wordlist-offset \<int> | Resume from a given position in the wordlist (defaults to 0)                                    |

### BurpSuite
GUI-Based collection of tools geared towards web app testing & a powerful proxy tool.  
	  \*Commercial versions include additional features, including a web app vuln scanner.  
  
#### Installing Cert

- Browsing to an HTTPS site while proxying traffic will present an “invalid certificate” warning.  
- Burp can generate its own SSL/TLS cert (essentially MITM) and importing it into Firefox in order to capture traffic.  
	  1. _Proxy_ > _Options_ > _Proxy Listeners_ > _Regenerate CA certificate_
	  2. Browse to [http://burp](http://burp) to find a link to the certificate and save the _cacert.der_ file
	  3. Drag ‘n’ drop to Firefox and select _Trust this CA to identify websites_

![](burp_cert.png)  

#### Proxy tool:
Can intercept any request sent from the browser before it is passed onto the server.  
  
Can change the fields w/in the request such as parameter names, form values, adding new headers, etc.  
- Allows us to test how an app handles unexpected arbitrary input.  
Ex - Modify a request to submit 30 chars w/in an input field w/ a size limit of 20 chars.  
  
##### Disable _Intercept_:  
When _Intercept_ is enabled, we have to manually click on _Forward_ to send each request towards its destination or click _Drop_ to not send the request.  
(Can disable _Intercept_ at start up w/in _User Options_ > _Misc_ > _Proxy Interception_)  
  
##### _Options_ tab

Will help set the proxy listener settings.  Default listener is localhost:8080
\*Same with Zap.  For Foxy Proxy setup, easiest to configure Burp for 8080 and Zap for 8081.

Burp:
- Proxy > Proxy Settings > Proxy Listeners
![](burp_proxies.png)

Zap:
- Tools > Options > Network > Local Servers/ Proxies
![](zap_proxies.png)
  
##### _HTTP history_

Will show once traffic has been sent through [BurpSuite](PWK--Tools--BurpSuite.html)  

#### Repeater tool:

- Used to modify requests, resend them, and review the responses.  
- Rt-click on a host w/in _Proxy_ > _HTTP history_, _Send to Repeater_  
- Can edit the request and _Send_ to server. Able to display the raw server response on the right side of the window (good for enumerating db w/ [SQL ORDER BY](9.4.5%20SQLi.md))  
  
#### Intruder tool:
- Allows automation basic username and password combinations for web logins  
  
1. Attempt login on site  
2.  Find POST method for attempt under _Proxy_ > _HTTP history_  
3. Rt-click > _Send to Intruder_  
4. Payload markers (**§**) will surround available payload positions  
5. _Clear_ and _Add_ markers to positions you want to attack  
6. After payloads are selected > _Start Attack_  
7. New results window will open  
8. Check response codes and verify  

##### Target subtab:  
- Info is pre-populated based on the request  
  
##### Positions subtab:  
- Used to mark which fields we want to inject payloads into when an attack is run.  
	- Cookie values and POST body values are marked as payload positions using a section sign (**§**) as the delimiter  
  
##### Payloads subtab:  
- Used to set payloads via sets and wordlists.  
	- Each set value matches the positions sequentially 
	- Verify which Payload Set and which Payload Type to work with....  
  
*Note: The “token value” can often contain special characters, so it's important to deselect the option to URL-encode them  
  
##### Resource Pool subtab:  
- Used to set up threading.  
	- If _Recursive Grep_ errors w/ "payloads cannot be used with multiple request threads", create new Resource Pool with 1 thread max.  

##### Options subtab:  
- With a _Recursive Grep_ payload, we can set up options to extract values from a response and inject them into the next request:  
	- Add a _Grep - Extract_  
	- Highlight value needing extraction - If multiple instances of a value are set (ie: cookies), burp will always use the first instance it finds.  
	- _Set Payloads_ > _Payload Sets_ to _Recursive Grep_. _Payloads_ > _Payload Options_ will fill in with the values set in _Grep - Extract_ section  
  
##### Attack Types:  
###### Sniper  
- Uses a single set of payloads.  
- Targets each payload position in turn and places each payload into that position in turn.  
- Useful for fuzzing a number of request parameters individually for common vulns  
- Number of requests generated is the product of the number of positions and the number of payloads in the payload set  
###### Battering Ram  
- Uses a single set of payloads.  
- Iterates through the payloads and places the same payload into all of the defined payload positions at once.  
- Useful where an attack requires the same input to be inserted in multiple places w/in the request (ex: username w/in a cookie and body parameter)  
- Number of requests generated is the number of payloads in the payload set.  
###### Pitchfork  
- Uses multiple sets of payloads.  
- Allows setting a unique payload set for each position.  
- First request places first payload from payload1 into position 1 & first payload from payload2 into position 2. Second request moves to 2nd payload from each set into respective positions.  
- Useful where attack requires different but related input to be inserted in multiple places w/in the request (ex: username in one paramter, known ID corresponding to that username into another)  
- Number of requests generated is the number of payloads in the smallest payload set.  
###### Cluster Bomb  
- Uses multiple sets of payloads.  
- Allows setting a unique payload set for each position.  
- Iterates through each payload set in turn so that all permutations of payload combinations are tested.  
- If there are 2 positions, the attack will place the 2st payload from payload2 into position 2 and iterated through all the payloads in payload1 in position 1.  
- Useful where attack requires different and unrelated or unknown input to be inserted in multiple places (ex: guessing creds w/ a username in one position and a password in another)  
- Number of requests generated is the product of the number of payloads in all defined payload sets - can be extremely large.

### Removed from course

#### dirb

Web Content Scanner.  Looks for existing (and/or hidden) Web Objects.
Essentially launches a dictionary based attack against a web server and analyzes the response.
	\*Creates a lot of noise within log files
  
Can be customized to search for specific directories, use custom dictionaries, set a custom cookie or header on each request, etc  

(**DirBuster** is a Java app similar to DIRB that offers multi-threading and a GUI interface.)

Usage:  
```bash
	dirb http://192.168.1.224/ /usr/share/wordlists/dirb/common.txt
```

| Options                             | Desc                                                                                                |
| ----------------------------------- | --------------------------------------------------------------------------------------------------- |
| -a \<agent_string>                  | Specify your custom USER_AGENT.  (Default is: "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)") |
| -b                                  | Don't squash or merge sequences of /../ or /./ in the given URL.                                    |
| -c \<cookie_string>                 | Set a cookie for the HTTP request.                                                                  |
| -E \<certificate>                   | Use the specified client certificate file.                                                          |
| -f                                  | Fine tunning of NOT_FOUND (404) detection.                                                          |
| -H \<header_string>                 | Add a custom header to the HTTP request.                                                            |
| -i                                  | Use case-insensitive Search.                                                                        |
| -l                                  | Print "Location" header when found.                                                                 |
| -N \<nf_code>                       | Ignore responses with this HTTP code.                                                               |
| -o \<output_file>                   | Save output to disk.                                                                                |
| -p \<proxy\[:port]>                 | Use this proxy. (Default port is 1080)                                                              |
| -P \<proxy_username:proxy_password> | Proxy Authentication.                                                                               |
| -r                                  | Don't Search Recursively.                                                                           |
| -R                                  | Interactive Recursion. (Ask in which directories you want to scan)                                  |
| -S                                  | Silent Mode. Don't show tested words. (For dumb terminals)                                          |
| -t                                  | Don't force an ending '/' on URLs.                                                                  |
| -u \<username:password>             | Username and password to use.                                                                       |
| -v                                  | Show Also Not Existent Pages.                                                                       |
| -w                                  | Don't Stop on WARNING messages.                                                                     |
| -x \<extensions_file>               | Amplify search with the extensions on this file.                                                    |
| -X \<extensions>                    | Amplify search with this extensions.                                                                |
| -z \<milisecs>                      | Amplify search with this extensions.                                                                |

#### nikto

Web Server scanner that tests for dangerous files and programs, vuln server versions, and various server config issues.  
- Not designed for stealth as it sends a lot of traffic and embeds info about itself in the User-Agent header.  
- Can scan multiple servers, ports, and as many pages as it can find.  
  
Usage:  
```bash
nikto -host=<domain> -<options>=
```

| Options                                | Desc                                                                                                    |     |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------- | --- |
| -ask                                   | Whether to ask about submitting updates                                                                 |     |
|                                        | **yes** - Ask about each (default)                                                                          |     |
|                                        | **no** - Don't ask, don't send                                                                              |     |
| -Cgidirs \<directory>                  | Scan these CGI dirs: "none", "all", or values like "/cgi/ /cgi-a/"                                      |     |
| -config \<file>                        | Use specified config file                                                                               |     |
| -Display \<output>                     | Turn on/off display outputs:                                                                            |     |
|                                        | **1** - Show redirects                                                                                      |     |
|                                        | **2** - Show cookies received                                                                               |     |
|                                        | **3** - Show all 200/OK responses                                                                           |     |
|                                        | **4** - Show URLs which require authentication                                                              |     |
|                                        | **D** - Debug output                                                                                        |     |
|                                        | **E** - Display all HTTP errors                                                                             |     |
|                                        | **P** - Print progress to STDOUT                                                                            |     |
|                                        | **S** - Scrub output of IPs and hostnames                                                                   |     |
|                                        | **V** - Verbose output                                                                                      |     |
| -dbcheck                               | Check database and other key files for syntax errors                                                    |     |
| -evasion \<technique>                  | Encoding technique:                                                                                     |     |
|                                        | **1** - Random URI encoding (non-UTF8)                                                                      |     |
|                                        | **2** - Directory self-reference (/./)                                                                      |     |
|                                        | **3** - Premature URL ending                                                                                |     |
|                                        | **4** - Prepend long random string                                                                          |     |
|                                        | **5** - Fake parameter                                                                                      |     |
|                                        | **6** - TAB as request spacer                                                                               |     |
|                                        | **7** - Change the case of the URL                                                                          |     |
|                                        | **8** - Use Windows directory separator (\)                                                                 |     |
|                                        | **A** - Use a carriage return (0x0d) as a request spacer                                                    |     |
|                                        | **B** - Use binary value 0x0b as a request spacer                                                           |     |
| -Format \<format>                      | Save file (-o) format:                                                                                  |     |
|                                        | **csv** - Comma-separated-value                                                                             |     |
|                                        | **htm** - HTML Format                                                                                       |     |
|                                        | **nbe** - Nessus NBE format                                                                                 |     |
|                                        | **sql** - Generic SQL (see docs for schema)                                                                 |     |
|                                        | **txt** - Plain text                                                                                        |     |
|                                        | **xml** - XML Format                                                                                        |     |
|                                        | \*\*(if not specified the format will be taken from the file extension passed to -output)                   |     |
| -Help                                  | Extended help information                                                                               |     |
| -host \<ip>                            | Target host                                                                                             |     |
| -404code                               | Ignore these HTTP codes as negative responses (always). Format is "302,301".                            |     |
| -404string                             | Ignore this string in response body content as negative response (always). Can be a regular expression. |     |
| -id \<auth>                            | Host authentication to use, format is id:pass or id:pass:realm                                          |     |
| -key \<filw>                           | Client certificate key file                                                                             |     |
| -list-plugins                          | List all available plugins, perform no testing                                                          |     |
| -maxtime \<time>                       | Maximum testing time per host (e.g., 1h, 60m, 3600s)                                                    |     |
| -mutate \<number>                      | Guess additional file names:                                                                            |     |
|                                        | **1** - Test all files with all root directories                                                            |     |
|                                        | **2** - Guess for password file names                                                                       |     |
|                                        | **3** - Enumerate user names via Apache (/~user type requests)                                              |     |
|                                        | **4** - Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)                             |     |
|                                        | **5** - Attempt to brute force sub-domain names, assume that the host name is the parent domain             |     |
|                                        | **6 **- Attempt to guess directory names from the supplied dictionary file                                  |     |
| -mutate-options                        | Provide information for mutates                                                                         |     |
| -nointeractive                         | Disables interactive features                                                                           |     |
| -nolookup                              | Disables DNS lookups                                                                                    |     |
| -nossl                                 | Disables the use of SSL                                                                                 |     |
| -no404                                 | Disables nikto attempting to guess a 404 page                                                           |     |
| -Option                                | Over-ride an option in nikto.conf, can be issued multiple times                                         |     |
| -output \<file>                        | Write output to this file ('.' for auto-name)                                                           |     |
| -Pause \<number>                       | Pause between tests (seconds, integer or float)                                                         |     |
| -Plugins \<plugins>                    | List of plugins to run (default: ALL)                                                                   |     |
| -port \<port>                                  | Port to use (default 80)                                                                                                  |     |
| -RSAcert \<file> | Client certificate file                                                                                                        |     |
| -root \<dir>                          | Prepend root value to all requests, format is /directory                                                |     |
| -Save                                  | Save positive responses to this directory ('.' for auto-name)                                           |     |
| -ssl                                   | Force ssl mode on port                                                                                  |     |
| -Tuning \<tuning>                      | Scan tuning:                                                                                            |     |
|                                        | **1** - Interesting File / Seen in logs                                                                 |     |
|                                        | **2** - Misconfiguration / Default File                                                                 |     |
|                                        | **3** - Information Disclosure                                                                          |     |
|                                        | **4** - Injection (XSS/Script/HTML)                                                                     |     |
|                                        | **5** - Remote File Retrieval - Inside Web Root                                                         |     |
|                                        | **6** - Denial of Service                                                                               |     |
|                                        | **7** - Remote File Retrieval - Server Wide                                                             |     |
|                                        | **8** - Command Execution / Remote Shell                                                                |     |
|                                        | **9** - SQL Injection                                                                                   |     |
|                                        | **0** - File Upload                                                                                     |     |
|                                        | **a** - Authentication Bypass                                                                           |     |
|                                        | **b** - Software Identification                                                                         |     |
|                                        | **c** - Remote Source Inclusion                                                                         |     |
|                                        | **d **- WebService                                                                                      |     |
|                                        | **e **- Administrative Console                                                                          |     |
|                                        | **x **- Reverse Tuning Options (i.e., include all except specified)                                     |     |
| -timeout \<time>                       | Timeout for requests (default 10 seconds)                                                               |     |
| -Userdbs                               | Load only user databases, not the standard databases                                                    |     |
|                                        | all - Disable standard dbs and load only user dbs                                                       |     |
|                                        | tests - Disable only db_tests and load udb_tests                                                        |     |
| -useragent                             | Over-rides the default useragent                                                                        |     |
| -until                                 | Run until the specified time or duration                                                                |     |
| -update                                | Update databases and plugins from CIRT.net                                                              |     |
| -useproxy                              | Use the proxy defined in nikto.conf, or argument http://server:port                                     |     |
| -Version                               | Print plugin and database versions                                                                      |     |
| -vhost \<ip?>                          | Virtual host (for Host header)                                                                          |     |


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