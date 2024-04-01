

# Misc
### meld

A visual diff and merge tool, targeted at developers.
Allows users to compare two or three files or directories visually, color-coding the different lines.

## exiftool

For reading, writing, manipulating image, audio, video and/ or PDF metadata


## binwalk

For analyzing, reverse engineering, and extracting firmware images.


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



### smbmap

Samba share enumerator

Usage:
```bash
smbmap -u 'apadmin' -p '<pw or hash>' -d ACME -Hh 10.1.3.30 -x 'net group "Domain Admins" /domain'
```

| Options | Desc |
| ---- | ---- |
| -H HOST | IP of host |
| --host-file FILE | File containing a list of hosts |
| -u USERNAME | Username, if omitted null session assumed |
| -p PASSWORD | Password or NTLM hash |
| --prompt | Prompt for a password |
| -s SHARE | Specify a share (default C$), ex 'C$' |
| -d DOMAIN | Domain name (default WORKGROUP) |
| -P PORT | SMB port (default 445) |
| -v | Return the OS version of the remote host |
| --admin | Just report if the user is an admin |
| --no-banner | Removes the banner from the top of the output |
| --no-color | Removes the color from output |
| --no-update | Removes the "Working on it" message |
| --timeout SCAN_TIMEOUT | Set port scan socket timeout. Default is .5 seconds |
|  |  |
| **Command Execution** | **Options for executing commands on the specified host** |
| -x COMMAND | Execute a command ex. 'ipconfig /all' |
| --mode CMDMODE | Set the execution method, wmi or psexec, default wmi |
|  |  |
| **Shard drive Search** | **Options for searching/enumerating the share of the specified host(s)** |
| -L | List all drives on the specified host, requires ADMIN rights. |
| -r [PATH] | Recursively list dirs and files (no share\path lists the root of ALL shares), ex. 'email/backup' |
| -A PATTERN | Define a file name pattern (regex) that auto downloads a file on a match (requires -r), not case sensitive, ex '(webglobal).(asaxconfig)' |
| -g FILE | Output to a file in a grep friendly format, used with -r (otherwise it outputs nothing), ex -g grep_out.txt |
| --csv FILE | Output to a CSV file, ex --csv shares.csv |
| --dir-only | List only directories, ommit files. |
| --no-write-check | Skip check to see if drive grants WRITE access. |
| -q | Quiet verbose output. Only shows shares you have READ or WRITE on, and suppresses file listing when performing a search (-A). |
| --depth DEPTH | Traverse a directory tree to a specific depth. Default is 5. |
| --exclude SHARE [SHARE ...] | Exclude share(s) from searching and listing, ex. --exclude ADMIN$ C$' |
|  |  |
| **File Content Search** | **Options for searching the content of files (must run as root), kind of experimental** |
| -F PATTERN | File content search, -F '[Pp]assword' (requires admin access to execute commands, and PowerShell on victim host) |
| --search-path PATH | Specify drive/path to search (used with -F, default C:\Users), ex 'D:\HR\' |
| --search-timeout TIMEOUT | Specifcy a timeout (in seconds) before the file search job gets killed. Default is 300 seconds. |
|  |  |
| **Filesystem interaction** | **Options for interacting with the specified host's filesystem** |
| --download PATH | Download a file from the remote system, ex.'C$\temp\passwords.txt' |
| --upload SRC DST | Upload a file to the remote system ex. '/tmp/payload.exe C$\temp\payload.exe' |
| --delete PATH TO FILE | Delete a remote file, ex. 'C$\temp\msf.exe' |
| --skip | Skip delete file confirmation prompt |



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

### nmap enumeration
```bash
sudo nmap -p 25 --script=smtp-enum* <target DOMAIN/ip>
```

### Connect through nc
```bash
nc -nv <IP> 25
```

### Connect through telnet - Windows
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

### swaks
- Swiss Army Knife for SMTP

```bash
swaks --to <victim> --from <abused email> --server <victim machine> --auth-user <abused user> -auth-password <abused pw> --attach <path to attachment ie: /home/kali/webdav/config.Library-ms> --header "test" --body "config file for software"
```


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

### nmap

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


### feroxbuster

Usage
```bash
feroxbuster -u http://127.1 -H Accept:application/json "Authorization: Bearer {token}" --burp
```

| Options                              | Desc                                                                                                                                        |                                                                      |                      |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------- |
| -h, --help                           | Print help (see a summary with '-h')                                                                                                        |                                                                      |                      |
| -V, --version                        | Print version                                                                                                                               |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Target selection                     |                                                                                                                                             |                                                                      |                      |
| -u, --url \<URL>                     | The target URL (required, unless \[--stdin                                                                                                  |                                                                      | --resume-from] used) |
| --stdin                              | Read url(s) from STDIN                                                                                                                      |                                                                      |                      |
| --resume-from \<STATE_FILE>          | State file from which to resume a partially complete scan (ex. --resume-from ferox-1606586780.state)                                        |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Composite settings:                  |                                                                                                                                             |                                                                      |                      |
| --burp                               | Set --proxy to hxxp://127.0.0.1:8080 and set --insecure to true                                                                             |                                                                      |                      |
| --burp-replay                        | Set --replay-proxy to hxxp://127.0.0.1:8080 and set --insecure to true                                                                      |                                                                      |                      |
| --smart                              | Set --auto-tune, --collect-words, and --collect-backups to true                                                                             |                                                                      |                      |
| --thorough                           | Use the same settings as --smart and set --collect-extensions to true                                                                       |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Proxy settings:                      |                                                                                                                                             |                                                                      |                      |
| -p, --proxy \<PROXY>                 | Proxy to use for requests (ex: http(s)://host:port, socks5(h)://host:port)                                                                  |                                                                      |                      |
| -P, --replay-proxy \<REPLAY_PROXY>   | Send only unfiltered requests through a Replay Proxy, instead of all requests                                                               |                                                                      |                      |
| -R, --replay-codes \<REPLAY_CODE>    | Status Codes to send through a Replay Proxy when found (default: --status-codes value)                                                      |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Request settings:                    |                                                                                                                                             |                                                                      |                      |
| -a, --user-agent \<USER_AGENT>       | Sets the User-Agent (default: feroxbuster/2.10.1)                                                                                           |                                                                      |                      |
| -A, --random-agent                   | Use a random User-Agent                                                                                                                     |                                                                      |                      |
| -x, --extensions \<FILE_EXTENSION>   | File extension(s) to search for (ex: -x php -x pdf js); reads values (newline-separated) from file if input starts with an @ (ex: @ext.txt) |                                                                      |                      |
| -m, --methods \<HTTP_METHODS>        | Which HTTP request method(s) should be sent (default: GET)                                                                                  |                                                                      |                      |
| --data \<DATA>                       | Request's Body; can read data from a file if input starts with an @ (ex: @post.bin)                                                         |                                                                      |                      |
| -H, --headers \<HEADER>              | Specify HTTP headers to be used in each request (ex: -H Header:val -H 'stuff: things')                                                      |                                                                      |                      |
| -b, --cookies \<COOKIE>              | Specify HTTP cookies to be used in each request (ex: -b stuff=things)                                                                       |                                                                      |                      |
| -Q, --query \<QUERY>                 | Request's URL query parameters (ex: -Q token=stuff -Q secret=key)                                                                           |                                                                      |                      |
| -f, --add-slash                      | Append / to each request's URL                                                                                                              |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Request filters:                     |                                                                                                                                             |                                                                      |                      |
| --dont-scan \<URL>                   | URL(s) or Regex Pattern(s) to exclude from recursion/scans                                                                                  |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Response filters:                    |                                                                                                                                             |                                                                      |                      |
| -S, --filter-size \<SIZE>            | Filter out messages of a particular size (ex: -S 5120 -S 4927,1970)                                                                         |                                                                      |                      |
| -X, --filter-regex \<REGEX>          | Filter out messages via regular expression matching on the response's body (ex: -X '^ignore me$')                                           |                                                                      |                      |
| -W, --filter-words \<WORDS>          | Filter out messages of a particular word count (ex: -W 312 -W 91,82)                                                                        |                                                                      |                      |
| -N, --filter-lines \<LINES>          | Filter out messages of a particular line count (ex: -N 20 -N 31,30)                                                                         |                                                                      |                      |
| -C, --filter-status \<STATUS_CODE>   | Filter out status codes (deny list) (ex: -C 200 -C 401)                                                                                     |                                                                      |                      |
| --filter-similar-to \<UNWANTED_PAGE> | Filter out pages that are similar to the given page (ex. --filter-similar-to hxxp://site.xyz/soft404)                                       |                                                                      |                      |
| -s, --status-codes \<STATUS_CODE>    | Status Codes to include (allow list) (default: All Status Codes)                                                                            |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Client settings:                     |                                                                                                                                             |                                                                      |                      |
| -T, --timeout \<SECONDS>             | Number of seconds before a client's request times out (default: 7)                                                                          |                                                                      |                      |
| -r, --redirects                      | Allow client to follow redirects                                                                                                            |                                                                      |                      |
| -k, --insecure                       | Disables TLS certificate validation in the client                                                                                           |                                                                      |                      |
| --server-certs \<PEM                 | DER>                                                                                                                                        | Add custom root certificate(s) for servers with unknown certificates |                      |
| --client-cert \<PEM>                 | Add a PEM encoded certificate for mutual authentication (mTLS)                                                                              |                                                                      |                      |
| --client-key \<PEM>                  | Add a PEM encoded private key for mutual authentication (mTLS)                                                                              |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Scan settings:                       |                                                                                                                                             |                                                                      |                      |
| -t, --threads \<THREADS>             | Number of concurrent threads (default: 50)                                                                                                  |                                                                      |                      |
| -n, --no-recursion                   | Do not scan recursively                                                                                                                     |                                                                      |                      |
| -d, --depth \<RECURSION_DEPTH>       | Maximum recursion depth, a depth of 0 is infinite recursion (default: 4)                                                                    |                                                                      |                      |
| --force-recursion                    | Force recursion attempts on all 'found' endpoints (still respects recursion depth)                                                          |                                                                      |                      |
| --dont-extract-links                 | Don't extract links from response body (html, javascript, etc...)                                                                           |                                                                      |                      |
| -L, --scan-limit <SCAN_LIMIT>        | Limit total number of concurrent scans (default: 0, i.e. no limit)                                                                          |                                                                      |                      |
| --parallel \<PARALLEL_SCANS>         | Run parallel feroxbuster instances (one child process per url passed via stdin)                                                             |                                                                      |                      |
| --rate-limit \<RATE_LIMIT>           | Limit number of requests per second (per directory) (default: 0, i.e. no limit)                                                             |                                                                      |                      |
| --time-limit \<TIME_SPEC>            | Limit total run time of all scans (ex: --time-limit 10m)                                                                                    |                                                                      |                      |
| -w, --wordlist \<FILE>               | Path or URL of the wordlist                                                                                                                 |                                                                      |                      |
| --auto-tune                          | Automatically lower scan rate when an excessive amount of errors are encountered                                                            |                                                                      |                      |
| --auto-bail                          | Automatically stop scanning when an excessive amount of errors are encountered                                                              |                                                                      |                      |
| -D, --dont-filter                    | Don't auto-filter wildcard responses                                                                                                        |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Dynamic collection settings:         |                                                                                                                                             |                                                                      |                      |
| -E, --collect-extensions             | Automatically discover extensions and add them to --extensions (unless they're in --dont-collect)                                           |                                                                      |                      |
| -B, --collect-backups                | Automatically request likely backup extensions for "found" urls                                                                             |                                                                      |                      |
| -g, --collect-words                  | Automatically discover important words from within responses and add them to the wordlist                                                   |                                                                      |                      |
| -I, --dont-collect \<FILE_EXTENSION> | File extension(s) to Ignore while collecting extensions (only used with --collect-extensions)                                               |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Output settings:                     |                                                                                                                                             |                                                                      |                      |
| -v, --verbosity                      | Increase verbosity level (use -vv or more for greater effect. \[CAUTION] 4 -v's is probably too much)                                       |                                                                      |                      |
| --silent                             | Only print URLs (or JSON w/ --json) + turn off logging (good for piping a list of urls to other commands)                                   |                                                                      |                      |
| -q, --quiet                          | Hide progress bars and banner (good for tmux windows w/ notifications)                                                                      |                                                                      |                      |
| --json                               | Emit JSON logs to --output and --debug-log instead of normal text                                                                           |                                                                      |                      |
| -o, --output \<FILE>                 | Output file to write results to (use w/ --json for JSON entries)                                                                            |                                                                      |                      |
| --debug-log \<FILE>                  | Output file to write log entries (use w/ --json for JSON entries)                                                                           |                                                                      |                      |
| --no-state                           | Disable state output file (*.state)                                                                                                         |                                                                      |                      |
|                                      |                                                                                                                                             |                                                                      |                      |
| Update settings:                     |                                                                                                                                             |                                                                      |                      |
| -U, --update                         | Update feroxbuster to the latest version                                                                                                    |                                                                      |                      |


### dirsearch

Brute force directories and files on a webserver

Usage
```bash
dirsearch [-u|--url] target [-e|--extensions] extensions [options]
```

| Options                                 | Desc                                                                                                                    |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| --version                               | show program's version number and exit                                                                                  |
| -h, --help                              | show this help message and exit                                                                                         |
|                                         |                                                                                                                         |
| **Mandatory**                               |                                                                                                                         |
| -u URL, --url=URL                       | Target URL(s), can use multiple flags                                                                                   |
| -l PATH, --url-file=PATH                | URL list file                                                                                                           |
| --stdin                                 | Read URL(s) from STDIN                                                                                                  |
| --cidr=CIDR                             | Target CIDR                                                                                                             |
| --raw=PATH                              | Load raw HTTP request from file (use `--scheme` flag to set the scheme)                                                 |
| -s SESSION_FILE, --session=SESSION_FILE | Session file                                                                                                            |
| --config=PATH                           | Full path to config file, see 'config.ini' for example (Default: config.ini)                                            |
|                                         |                                                                                                                         |
| **Dictionary Settings**                     |                                                                                                                         |
| -w WORDLISTS, --wordlists=WORDLISTS     | Customize wordlists (separated by commas)                                                                               |
| -e EXTENSIONS, --extensions=EXTENSIONS  | Extension list separated by commas (e.g. php,asp)                                                                       |
| -f, --force-extensions                  | Add extensions to the end of every wordlist entry. By default dirsearch only replaces the %EXT% keyword with extensions |
| -O, --overwrite-extensions              | Overwrite other extensions in the wordlist with your extensions (selected via `-e`)                                     |
| --exclude-extensions=EXTENSIONS         | Exclude extension list separated by commas (e.g. asp,jsp)                                                               |
| --remove-extensions                     | Remove extensions in all paths (e.g. admin.php -> admin)                                                                |
| --prefixes=PREFIXES                     | Add custom prefixes to all wordlist entries (separated by commas)                                                       |
| --suffixes=SUFFIXES                     | Add custom suffixes to all wordlist entries, ignore directories (separated by commas)                                   |
| -U, --uppercase                         | Uppercase wordlist                                                                                                      |
| -L, --lowercase                         | Lowercase wordlist                                                                                                      |
| -C, --capital                           | Capital wordlist                                                                                                        |
|                                         |                                                                                                                         |
| **General Settings**                        |                                                                                                                         |
| -t THREADS, --threads=THREADS           | Number of threads                                                                                                       |
| -r, --recursive                         | Brute-force recursively                                                                                                 |
| --deep-recursive                        | Perform recursive scan on every directory depth (e.g. api/users -> api/)                                                |
| --force-recursive                       | Do recursive brute-force for every found path, not only directories                                                     |
| -R DEPTH, --max-recursion-depth=DEPTH   | Maximum recursion depth                                                                                                 |
| --recursion-status=CODES                | Valid status codes to perform recursive scan, support ranges (separated by commas)                                      |
| --subdirs=SUBDIRS                       | Scan sub-directories of the given URL[s] (separated by commas)                                                          |
| --exclude-subdirs=SUBDIRS               | Exclude the following subdirectories during recursive scan (separated by commas)                                        |
| -i CODES, --include-status=CODES        | Include status codes, separated by commas, support ranges (e.g. 200,300-399)                                            |
| -x CODES, --exclude-status=CODES        | Exclude status codes, separated by commas, support ranges (e.g. 301,500-599)                                            |
| --exclude-sizes=SIZES                   | Exclude responses by sizes, separated by commas (e.g. 0B,4KB)                                                           |
| --exclude-text=TEXTS                    | Exclude responses by text, can use multiple flags                                                                       |
| --exclude-regex=REGEX                   | Exclude responses by regular expression                                                                                 |
| --exclude-redirect=STRING               | Exclude responses if this regex (or text) matches redirect URL (e.g. '/index.html')                                     |
| --exclude-response=PATH                 | Exclude responses similar to response of this page, path as input (e.g. 404.html)                                       |
| --skip-on-status=CODES                  | Skip target whenever hit one of these status codes, eparated by commas, support ranges                                  |
| --min-response-size=LENGTH              | Minimum response length                                                                                                 |
| --max-response-size=LENGTH              | Maximum response length                                                                                                 |
| --max-time=SECONDS                      | Maximum runtime for the scan                                                                                            |
| --exit-on-error                         | Exit whenever an error occurs                                                                                           |
|                                         |                                                                                                                         |
| **Request Settings**                        |                                                                                                                         |
| -m METHOD, --http-method=METHOD         | HTTP method (default: GET)                                                                                              |
| -d DATA, --data=DATA                    | HTTP request data                                                                                                       |
| --data-file=PATH                        | File contains HTTP request data                                                                                         |
| -H HEADERS, --header=HEADERS            | HTTP request header, can use multiple flags                                                                             |
| --header-file=PATH                      | File contains HTTP request headers                                                                                      |
| -F, --follow-redirects                  | Follow HTTP redirects                                                                                                   |
| --random-agent                          | Choose a random User-Agent for each request                                                                             |
| --auth=CREDENTIAL                       | Authentication credential (e.g. user:password or bearer token)                                                          |
| --auth-type=TYPE                        | Authentication type (basic, digest, bearer, ntlm, jwt, oauth2)                                                          |
| --cert-file=PATH                        | File contains client-side certificate                                                                                   |
| --key-file=PATH                         | File contains client-side certificate private key (unencrypted)                                                         |
| --user-agent=USER_AGENT                 |                                                                                                                         |
| --cookie=COOKIE                         |                                                                                                                         |
|                                         |                                                                                                                         |
| **Connection Settings**                     |                                                                                                                         |
| --timeout=TIMEOUT                       | Connection timeout                                                                                                      |
| --delay=DELAY                           | Delay between requests                                                                                                  |
| --proxy=PROXY                           | Proxy URL (HTTP/SOCKS), can use multiple flags                                                                          |
| --proxy-file=PATH                       | File contains proxy servers                                                                                             |
| --proxy-auth=CREDENTIAL                 | Proxy authentication credential                                                                                         |
| --replay-proxy=PROXY                    | Proxy to replay with found paths                                                                                        |
| --tor                                   | Use Tor network as proxy                                                                                                |
| --scheme=SCHEME                         | Scheme for raw request or if there is no scheme in the URL (Default: auto-detect)                                       |
| --max-rate=RATE                         | Max requests per second                                                                                                 |
| --retries=RETRIES                       | Number of retries for failed requests                                                                                   |
| --ip=IP                                 | Server IP address                                                                                                       |
|                                         |                                                                                                                         |
| **Advanced Settings**                       |                                                                                                                         |
| --crawl                                 | Crawl for new paths in responses                                                                                        |
|                                         |                                                                                                                         |
| **View Settings**                           |                                                                                                                         |
| --full-url                              | Full URLs in the output (enabled automatically in quiet mode)                                                           |
| --redirects-history                     | Show redirects history                                                                                                  |
| --no-color                              | No colored output                                                                                                       |
| -q, --quiet-mode                        | Quiet mode                                                                                                              |
|                                         |                                                                                                                         |
| **Output Settings**                         |                                                                                                                         |
| -o PATH, --output=PATH                  | Output file                                                                                                             |
| --format=FORMAT                         | Report format (Available: simple, plain, json, xml, md, csv, html, sqlite)                                              |
| --log=PATH                              | Log file                                                                                                                |


### BurpSuite

GUI-Based collection of tools geared towards web app testing & a powerful proxy tool.  
	  \*Commercial versions include additional features, including a web app vuln scanner.

When using cmdline, append the *--proxy* switch in order to send request through the BurpSuite proxy
Ex
```bash
curl -i http://megacorpone.com --proxy 127.0.0.1:8080
```
  
#### Installing Cert

- Browsing to an HTTPS site while proxying traffic will present an “invalid certificate” warning.  
- Burp can generate its own SSL/TLS cert (essentially MITM) and importing it into Firefox in order to capture traffic.  
	  1. _Proxy_ > _Options_ > _Proxy Listeners_ > _Regenerate CA certificate_
	  2. Browse to [http://burp](http://burp) to find a link to the certificate and save the _cacert.der_ file
	  3. Drag ‘n’ drop to Firefox and select _Trust this CA to identify websites_

![](burp_cert.png)  

#### Proxy tool
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

#### Repeater tool

- Used to modify requests, resend them, and review the responses.  
- Rt-click on a host w/in _Proxy_ > _HTTP history_, _Send to Repeater_  
- Can edit the request and _Send_ to server. Able to display the raw server response on the right side of the window (good for enumerating db w/ [SQL ORDER BY](9.4.5%20SQLi.md))  
  
#### Intruder tool
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

#### Decoder Tool

Allows for hashing for numerous types
Allows for easy Encoding and Decoding for various types & offers smart decoding
- URL
- HTML
- Base64
- ASCII hex
- Hex
- Octal
- Binary
- Gzip

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


## SQLi

### impacket-mssqlclient
- Linux application that allows interacting with Windows MSSQL servers.

Usage
```bash
impacket-mssqlclient [[domain/]username[:password]@]<targetName or IP>

impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```

| Options | Desc |
| ---- | ---- |
| -h, --help | show this help message and exit |
| -port PORT | target MSSQL port (default 1433) |
| -db DB | MSSQL database instance (default None) |
| -windows-auth | whether or not to use Windows Authentication (default False) |
| -debug | Turn DEBUG output ON |
| -show | show the queries |
| -file FILE | input file with commands to execute in the SQL shell |
|  |  |
| authentication: |  |
| -hashes LMHASH:NTHASH | NTLM hashes, format is LMHASH:NTHASH |
| -no-pass | don't ask for password (useful for -k) |
| -k | Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters.<br>If valid credentials cannot be found, it will use the ones specified in the command line |
| -aesKey hex key | AES key to use for Kerberos Authentication (128 or 256 bits) |
| -dc-ip ip address | IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter |

### sqlmap
\*\*\*\*\*\*NOT ALLOWED\*\*\*\*\*\*\*

Tests and exploits SQL Injection vulns.  
  
Saves reports in /home/kali/.local/share/sqlmap/output/<\domain\>  
  
***Note:** Always use “ ” around the domain  
  
  
Usage:  
```bash
sqlmap -u "http://192.168.xxx.10/debug.php?id=1" -p id
```

| Option            | Desc                                                                                                                                   |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| -h, -hh           | Show basic help message and exit                                                                                                       |
| --version         | Show program's version number and exit                                                                                                 |
| **-v** <#>        | Verbosity level _#_: 0-6 (default 1)                                                                                                   |
|                   |                                                                                                                                        |
| **Target**        | \*At least one of these options has to be provided to define the target(s)                                                             |
| -u , --url=       | Target URL (e.g. "hXXp://www.site[.]com/vuln.php?id=1")                                                                                |
| -g _GOOGLEDORK_   | Process Google dork results as target URLs                                                                                             |
|                   |                                                                                                                                        |
| **Request**       | These options can be used to specify how to connect to the target URL                                                                  |
| --data=           | Data string to be sent through POST (e.g. "id=1")                                                                                      |
| --cookie=         | HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")                                                                                  |
| --random-agent    | Use randomly selected HTTP User-Agent header value                                                                                     |
| --proxy=          | Use a proxy to connect to the target URL                                                                                               |
| --tor             | Use Tor anonymity network                                                                                                              |
| --check-tor       | Check to see if Tor is used properly                                                                                                   |
|                   |                                                                                                                                        |
| **Injection**     | These options can be used to specify which parameters to test for,<br>provide custom injection payloads and optional tampering scripts |
| -p                | Testable parameter(s)                                                                                                                  |
| --dbms=           | Force back-end DBMS to provided value                                                                                                  |
|                   |                                                                                                                                        |
| **Detection**     | These options can be used to customize the detection phase                                                                             |
| --level=          | Level of tests to perform (1-5, default 1)                                                                                             |
| --risk=           | Risk of tests to perform (1-3, default 1)                                                                                              |
|                   |                                                                                                                                        |
| **Techniques**    | These options can be used to tweak testing of specific SQL injection techniques                                                        |
| --technique=      | SQL injection techniques to use (default "BEUSTQ")                                                                                     |
|                   |                                                                                                                                        |
| **Enumeration**   | These options can be used to enumerate the back-end db mgmt system info,<br>structure and data contained in the tables                 |
| -a, --all         | Retrieve everything                                                                                                                    |
| -b, --banner      | Retrieve DBMS banner                                                                                                                   |
| --current-user    | Retrieve DBMS current user                                                                                                             |
| --current-db      | Retrieve DBMS current database                                                                                                         |
| --passwords       | Enumerate DBMS users password hashes                                                                                                   |
| --tables          | Enumerate DBMS database tables                                                                                                         |
| --columns         | Enumerate DBMS database table columns                                                                                                  |
| --dbs             | Enumerate DBMS databases                                                                                                               |
| --schema          | Enumerate DBMS schema                                                                                                                  |
| --dump            | Dump DBMS database table entries                                                                                                       |
| --dump-all        | Dump all DBMS databases tables entries                                                                                                 |
| -D                | DBMS database to enumerate                                                                                                             |
| -T                | DBMS database table(s) to enumerate                                                                                                    |
| -C                | DBMS database table column(s) to enumerate                                                                                             |
| --sql-shell       | Prompt for an interactive SQL shell                                                                                                    |
|                   |                                                                                                                                        |
| **OS access**     | These options can be used to access the back-end db mgmt system underlying operating system                                            |
| --os-shell        | Prompt for an interactive operating system shell                                                                                       |
| --os-pwn          | Prompt for an OOB shell, Meterpreter or VNC                                                                                            |
|                   |                                                                                                                                        |
| **General**       | These options can be used to set some general working parameters                                                                       |
| --batch           | Never ask for user input, use the default behavior                                                                                     |
| --flush-session   | Flush session files for current target                                                                                                 |
| --threads=x       | Use x concurrent threads (Best to speed up Blind Time-based)                                                                           |
|                   |                                                                                                                                        |
| **Miscellaneous** | These options do not fit into any other category                                                                                       |
| --wizard          | Simple wizard interface for beginner users                                                                                             |


# Target Recon

### exiftool
- Metadata analyzer

Usage
```bash
exiftool [OPTIONS] file
```

| Options                             | Desc                                    |
| ----------------------------------- | --------------------------------------- |
| TAG OPERATIONS                      |                                         |
| -TAG or --TAG                       | Extract or exclude specified tag        |
| -TAG\[+-^]=\[VALUE]                 | Write new value for tag                 |
| -TAG\[+-]<=DATFILE                  | Write tag value from contents of file   |
| -\[+]TAG\[+-]<SRCTAG                | Copy tag value (see -tagsFromFile)      |
| -tagsFromFile SRCFILE               | Copy tag values from file               |
| -x TAG      (-exclude)              | Exclude specified tag                   |
|                                     |                                         |
| INPUT-OUTPUT FORMATTING             |                                         |
| -args       (-argFormat)            | Format metadata as exiftool arguments   |
| -b          (-binary)               | Output metadata in binary format        |
| -c FMT      (-coordFormat)          | Set format for GPS coordinates          |
| -charset \[\[TYPE=]CHARSET]         | Specify encoding for special characters |
| -csv\[\[+]=CSVFILE]                 | Export/import tags in CSV format        |
| -csvDelim STR                       | Set delimiter for CSV file              |
| -d FMT      (-dateFormat)           | Set format for date/time values         |
| -D          (-decimal)              | Show tag ID numbers in decimal          |
| -E,-ex,-ec  (-escape(HTML\|XML\|C)) | Escape tag values for HTML, XML or C    |
| -f          (-forcePrint)           | Force printing of all specified tags    |
| -g\[NUM...]  (-groupHeadings)       | Organize output by tag group            |
| -G\[NUM...]  (-groupNames)          | Print group name for each tag           |
| -h          (-htmlFormat)           | Use HTML formatting for output          |
| -H          (-hex)                  | Show tag ID numbers in hexadecimal      |
| -htmlDump\[OFFSET]                  | Generate HTML-format binary dump        |
| -j\[\[+]=JSONFILE] (-json)          | Export/import tags in JSON format       |
| -l          (-long)                 | Use long 2-line output format           |
| -L          (-latin)                | Use Windows Latin1 encoding             |
| -lang \[LANG]                       | Set current language                    |
| -listItem INDEX                     | Extract specific item from a list       |
| -n          (--printConv)           | No print conversion                     |
| -p\[-] STR   (-printFormat)         | Print output in specified format        |
| -php                                | Export tags as a PHP Array              |
| -s\[NUM]     (-short)               | Short output format (-s for tag names)  |
| -S          (-veryShort)            | Very short output format                |
| -sep STR    (-separator)            | Set separator string for list items     |
| -sort                               | Sort output alphabetically              |
| -struct                             | Enable output of structured information |
| -t          (-tab)                  | Output in tab-delimited list format     |
| -T          (-table)                | Output in tabular format                |
| -v\[NUM]     (-verbose)             | Print verbose messages                  |
| -w\[+\|!] EXT (-textOut)            | Write (or overwrite!) output text files |
| -W\[+\|!] FMT (-tagOut)             | Write output text file for each tag     |
| -Wext EXT   (-tagOutExt)            | Write only specified file types with -W |
| -X          (-xmlFormat)            | Use RDF/XML output format               |
|                                     |                                         |
| PROCESSING CONTROL                  |                                         |
| -a          (-duplicates)           | Allow duplicate tags to be extracted    |
| -e          (--composite)           | Do not generate composite tags          |
| -ee\[NUM]    (-extractEmbedded)     | Extract information from embedded files |
| -ext\[+] EXT (-extension)           | Process files with specified extension  |
| -F\[OFFSET]  (-fixBase)             | Fix the base for maker notes offsets    |
| -fast\[NUM]                         | Increase speed when extracting metadata |
| -fileOrder\[NUM] \[-]TAG            | Set file processing order               |
| -i DIR      (-ignore)               | Ignore specified directory name         |
| -if\[NUM] EXPR                      | Conditionally process files             |
| -m          (-ignoreMinorErrors)    | Ignore minor errors and warnings        |
| -o OUTFILE  (-out)                  | Set output file or directory name       |
| -overwrite_original                 | Overwrite original by renaming tmp file |
| -overwrite_original_in_place        | Overwrite original by copying tmp file  |
| -P          (-preserve)             | Preserve file modification date/time    |
| -password PASSWD                    | Password for processing protected files |
| -progress\[NUM]\[:\[TITLE]]         | Show file progress count                |
| -q          (-quiet)                | Quiet processing                        |
| -r[.]       (-recurse)              | Recursively process subdirectories      |
| -scanForXMP                         | Brute force XMP scan                    |
| -u          (-unknown)              | Extract unknown tags                    |
| -U          (-unknown2)             | Extract unknown binary tags too         |
| -wm MODE    (-writeMode)            | Set mode for writing/creating tags      |
| -z          (-zip)                  | Read/write compressed information       |
|                                     |                                         |
| OTHER                               |                                         |
| -@ ARGFILE                          | Read command-line arguments from file   |
| -k          (-pause)                | Pause before terminating                |
| -list\[w\|f\|wf\|g\[NUM]\|d\|x]     | List various exiftool capabilities      |
| -ver                                | Print exiftool version number           |
| --                                  | End of options                          |
|                                     |                                         |
| SPECIAL FEATURES                    |                                         |
| -geotag TRKFILE                     | Geotag images from specified GPS log    |
| -globalTimeShift SHIFT              | Shift all formatted date/time values    |
| -use MODULE                         | Add features from plug-in module        |
|                                     |                                         |
| UTILITIES                           |                                         |
| -delete_original\[!]                | Delete "_original" backups              |
| -restore_original                   | Restore from "_original" backups        |
|                                     |                                         |
| ADV OPTIONS                         |                                         |
| -api OPT\[\[^]=\[VAL]]              | Set ExifTool API option                 |
| -common_args                        | Define common arguments                 |
| -config CFGFILE                     | Specify configuration file name         |
| -echo\[NUM] TEXT                    | Echo text to stdout or stderr           |
| -efile\[NUM]\[!] TXTFILE            | Save names of files with errors         |
| -execute\[NUM]                      | Execute multiple commands on one line   |
| -fileNUM ALTFILE                    | Load tags from alternate file           |
| -list_dir                           | List directories, not their contents    |
| -srcfile FMT                        | Process a different source file         |
| -stay_open FLAG                     | Keep reading -@ argfile even after EOF  |
| -userParam PARAM\[\[^]=\[VAL]]      | Set user parameter (API UserParam opt)  |

### Removed from course

#### fingerprintjs2
JS library which can be used to gather all information about clients visiting a site it's utilized in.    

```bash
cd /var/www/html  
mkdir fp  
  
sudo wget https://github.com/fingerprintjs/fingerprintjs/archive/2.1.4.zip  
sudo unzip 2.1.4.zip  
sudo mv fingerprintjs-2.1.4/ fp/  
  
cd fp  
vim index.html
```


Info should reveal browser User Agent string, its localization, the installed browser plugins & relative version, generic info regarding the underlying OS platform, and other details.  
  
  
**Ex index.html:**  
```html
<!doctype html>  
<html>  
<head>  
  <title>Fingerprintjs2 test</title>  
</head>  
<body>  
  <h1>Insert whatever you want shown on the site</h1>  
  
  <p>Your browser fingerprint: <strong id="fp"></strong></p>  
  <p><code id="time"/></p>  
  <p><span id="details"/></p>  
    
  <script src="fingerprint2.js"></script>  
  <script>  
var d1 = new Date();  
var options = {};  
        
Fingerprint2.get(options, function (components) {  
var values = components.map(function (component) { return component.value })  
var murmur = Fingerprint2.x64hash128(values.join(''), 31)  
var clientfp = "Client browser fingerprint: " + murmur + "\n\n";  
var d2 = new Date();  
var timeString = "Time to calculate fingerprint: " + (d2 - d1) + "ms\n\n";  
var details = "<strong>Detailed information: </strong><br />";  
  
if(typeof window.console !== "undefined") {  
for (var index in components) {  
var obj = components[index];  
var value = obj.value;  
  
if (value !== null) {  
var line = obj.key + " = " + value.toString().substr(0, 150);  
details += line + "\n";  
}  
}  
}  
//document.querySelector("#details").innerHTML = details   
//document.querySelector("#fp").textContent = murmur   
//document.querySelector("#time").textContent = timeString  
  
var xmlhttp = new XMLHttpRequest();  
xmlhttp.open("POST", "/fp/js.php");  
xmlhttp.setRequestHeader("Content-Type", "application/txt");  
xmlhttp.send(clientfp + timeString + details);  
});  
  </script>  
</body>  
</html>
```

```html
<!doctype html>  
<html>  
<head>  
  <title>Fingerprintjs2 test</title>  
</head>  
<body>  
  <h1>Insert whatever you want shown on the site</h1>  
  
  <p>Your browser fingerprint: <strong id="fp"></strong></p>  
  <p><code id="time"/></p>  
  <p><span id="details"/></p>  
    
  <script src="fingerprint2.js"></script>  
  <script>  
var d1 = new Date();  
var options = {};  
        
Fingerprint2.get(options, function (components) {  
var values = components.map(function (component) { return component.value })  
var murmur = Fingerprint2.x64hash128(values.join(''), 31)  
var clientfp = "Client browser fingerprint: " + murmur + "\n\n";  
var d2 = new Date();  
var timeString = "Time to calculate fingerprint: " + (d2 - d1) + "ms\n\n";  
var details = "<strong>Detailed information: </strong><br />";  
  
if(typeof window.console !== "undefined") {  
for (var index in components) {  
var obj = components[index];  
var value = obj.value;  
  
if (value !== null) {  
var line = obj.key + " = " + value.toString().substr(0, 150);  
details += line + "\n";  
}  
}  
}  
//document.querySelector("#details").innerHTML = details   
//document.querySelector("#fp").textContent = murmur   
//document.querySelector("#time").textContent = timeString  
  
var xmlhttp = new XMLHttpRequest();  
xmlhttp.open("POST", "/fp/js.php");  
xmlhttp.setRequestHeader("Content-Type", "application/txt");  
xmlhttp.send(clientfp + timeString + details);  
});  
  </script>  
</body>  
</html>
```
 - Line 18: Invokes the _Fingerprint2.get_ static function to start the process  
 - Line 19: _Components_ variable returned by the library is an array containing all the info extracted from the client  
 - Line 20: ^ data is passed to the _murmur_ hash function in order to create a hash fingerprint of the browser  
 - Line 21: Added Ajax which will transer the extracted info to our attacking webserver.  
 - Lines 37-39: Values are displayed within the page to the client..... hence commented out.  
 - Lines 41-44: Use _XMLHttpRequest_ JS API to send the extracted data to the attacking web server via a POST request.  
	 - Issued against the same server where the malicious web page is stored.  
		 - Hence why the _xmlhttp.open_ method doesn't specify an IP  
  

**Ex PHP code which processes the POST request from above (Lines 41-44):**  
```php
<?php  
$data = "Client IP Address: " . $_SERVER['REMOTE_ADDR'] . "\n";  
$data .= file_get_contents('php://input');  
$data .= "---------------------------------\n\n";  
file_put_contents('/var/www/html/fp/fingerprint.txt', print_r($data, true), FILE_APPEND | LOCK_EX);  
?>
```
 - Line 2: First extracts the client IP from the _$_SERVER_ array (contains server & execution environment info)  
 - Line 5: Concats the IP to the text string received from the JS POST request & written to the **fingerprint.txt** file in the **/var/www/html/fp** dir  
 - Use of _FILE_APPEND_ flag allows storing of multiple fingerprints to the same file.  
  
  
In order for this to work, Apache _www-data_ user needs to be able to write to the **fp** dir:  
```bash
sudo chown www-data:www-data fp
```


### searchsploit

|     | Options                  | Desc                                                                                                                                                                      |
| --- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|     |                          |                                                                                                                                                                           |
|     | **Search Terms**         |                                                                                                                                                                           |
|     | -c, --case \[term]       | Perform a case-sensitive search (Default is inSEnsITiVe)                                                                                                                  |
|     | -e, --exact \[term]      | Perform an EXACT & order match on exploit title (Default is an AND match on each term) [Implies "-t"]  <br>e.g. "WordPress 4.1" would not be detect "WordPress Core 4.1") |
|     | -s, --strict             | Perform a strict search, so input values must exist, disabling fuzzy search for version range<br>e.g. "1.1" would not be detected in "1.0 < 1.3")                         |
|     | -t, --title \[term]      | Search JUST the exploit title (Default is title AND the file's path)                                                                                                      |
|     | --exclude="term"         | Remove values from results. By using "" to separate, you can chain multiple values<br>e.g. --exclude="term1\|term2\|term3"                                                |
|     | --cve \[CVE]             | Search for Common Vulnerabilities and Exposures (CVE) value                                                                                                               |
|     |                          |                                                                                                                                                                           |
|     | **Output**               |                                                                                                                                                                           |
|     | -j, --json \[term]       | Show result in JSON format                                                                                                                                                |
|     | -o, --overflow \[term]   | Exploit titles are allowed to overflow their columns                                                                                                                      |
|     | -p, --path \[EDB-ID]     | Show the full path to an exploit (and also copies the path to the clipboard if possible)                                                                                  |
|     | -v, --verbose            | Display more information in output                                                                                                                                        |
|     | -w, --www \[term]        | Show URLs to Exploit-DB.com rather than the local path                                                                                                                    |
|     | --id                     | Display the EDB-ID value rather than local path                                                                                                                           |
|     | --disable-colour         | Disable colour highlighting in search results                                                                                                                             |
|     |                          |                                                                                                                                                                           |
|     | **Non**-**Searching**    |                                                                                                                                                                           |
|     | -m, --mirror \[EDB-ID]   | Mirror (aka copies) an exploit to the current working directory                                                                                                           |
|     | -x, --examine  \[EDB-ID] | Examine (aka opens) the exploit using $PAGER                                                                                                                              |
|     | -h, --help               | Show this help screen                                                                                                                                                     |
|     | -u, --update             | Check for and install any exploitdb package updates (brew, deb & git)                                                                                                     |
|     |                          |                                                                                                                                                                           |
|     | **Automation**           |                                                                                                                                                                           |
|     | --nmap \[file.xml]       | Checks all results in Nmap's XML output with service version<br>e.g.: nmap \[host] -sV -oX file.xml                                                                       |

# AV Evasion




### Shellter
Shellcode injection tool capable of bypassing AntiVirus apps.  
  
** Requires **wine32**  
** Compatible ONLY w/ [x86 architecture](x86%20Architecture.md)  
  
Performs a thorough analysis of the target PE file and the execution paths.  
It then determines where it can inject our shellcode, without relying on traditional injection techniques that are easily caught by AV engines.  
Including changing of PE file section permissions, creating new sections, and so on.  
Finally, Shellter attempts to use the existing [PE Import Address Table](Portable%20Executable.md) (IAT) entries to locate functions that will be used for the memory allocation, transfer, and execution of our payload.  
  
Shellter obfuscates both the payload as well as the payload decoder before injecting them into the PE  
  
#### Operation  
Mode - Auto & Manual.  
Manual allows us to adjust options with much more granularity  
PE Target - Requires full path to binary  
Creates a backup of binary first  
Stealth Mode - Attempts to restore the execution flow after the payload is executed  
Custom payloads need to terminate by exiting the current thread.  
Payload Options - Choice of listed or custom payload  
For Listed, need to select ‘L’, then payload index.  

#### Tips & Tricks

• **Find a few 32-bit standalone legitimate executables** that always work for you and stick with them for as long as they do the job.  
However, take in serious consideration what is discussed in this [article](https://www.shellterproject.com/an-important-tip-for-shellter-usage/), thus avoid using executables of popular applications when not needed.  
Unless you are using the Steath Mode for a RedTeam job because you want to trick the victim to run a specific backdoored application, there is no reason to use a different executable every time. Just make sure you use a clean one.  
  
◇ Before using a legitimate executable, try to scan it using an online multi-AV scanner. Sometimes **AVs do produce false positives**, so it’s good to know that your chosen executable wasn’t detected as something malicious in the first place.  
  
◇ **Don’t use packed executables!**  
If you get a notification that the executable is probably packed, then get another one.  
  
◇ **Don’t use Shellter with executables produced by other pentesting tools or frameworks.** These have possibly been flagged already by many AV vendors. Since Shellter actually traces the execution flow of the target application, you also risk to ‘infect’ yourself if you do that.  
  
◇ **If you just need to execute your payload during a pentesting job, you don’t need to enable the Stealth mode feature.** This feature is useful during Red Team engagements, since it enables Shellter to maintain the original functionality of the infected application.  
  
◇ **If you decide to use the Dynamic Thread Context Keys (DTCK) feature then try to avoid enabling obfuscation for every single step.** This feature enables an extra filtering stage which reduces even more the available injection locations, so it’s better not to increase a lot the size of the code to be injected.  
So as a rule of thumb, in this case just choose to obfuscate the IAT handler. If you use command line just add ‘––polyIAT’ and don’t enable any other obfuscation features.  
  
◇ **If you want to inject a DLL with a reflective loader, try to keep your DLL as small as possible** and use an executable that has a section, where the code has been traced, that can fit it.  
Think before you do!  
  
◇ If you are not sure about how to use Shellter, and what each feature does, then **use the Auto Mode**. It has been put there for this purpose. Use it!  
  
◇ **If you are just interested in bypassing the AV and execute your payload,** hence not looking at the Stealth Mode feature, then **various uninstallers dropped by installed programs might be what you need**.  
These are generally standalone and small in size, which makes them perfect for generic usage.  
  
◇ **If you really want to use the Manual Mode, make sure you understand enough what each feature does.** Reading the documentation about Shellter is also something you should do first.  
  
◇ **If you use the Manual Mode, don’t just trace for a very small number of instructions.** The point and one of the unique features of Shellter are it’s ability to trace down the execution flow so that it doesn’t inject into predictable locations. Don’t ruin it for yourself.  
Usually, 50k instructions should be fine, but as you go deeper in the execution flow the better it gets.  
If you think that reaching the amount of instructions that you chose it takes too long, you can always interrupt the tracing stage by pressing CTRL+C and proceed with the rest of the injection process.  
  
**PS: Shellter tries its best to avoid any mistakes while completely automating the process of dynamic PE infection.  
However, this is a complicated task and for that reason there is always a small possibility for failure.  
Following the list of tips and tricks presented here, will give you a good starting point for using Shellter.  
Keep in mind that while Shellter will try to handle everything for you, it does need your common sense to give you its best.**

### Veil

Tool designed to generate metasploit payloads that bypass common anti-virus solutions.  

#### Install
```bash
apt -y install veil  
/usr/share/veil/config/setup.sh --force --silent
```

#### Main Menu
```bash
$ ./Veil.py  
===============================================================================  
                             Veil | [Version]: 3.1.6  
===============================================================================  
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework  
===============================================================================  
  
Main Menu  
  
  2 tools loaded  
  
Available Tools:  
  
  1)  Evasion  
  2)  Ordnance  
  
Available Commands:  
  
  exit      Completely exit Veil  
  info      Information on a specific tool  
  list      List available tools  
  options     Show Veil configuration  
  update      Update Veil  
  use     Use a specific tool  
  
Veil>:
```

#### Usage
```bash
$ ./Veil.py --help  
usage: Veil.py [--list-tools] [-t TOOL] [--update] [--setup] [--config]  
               [--version] [--ip IP] [--port PORT] [--list-payloads]  
               [-p [PAYLOAD]] [-o OUTPUT-NAME]  
               [-c [OPTION=value [OPTION=value ...]]]  
               [--msfoptions [OPTION=value [OPTION=value ...]]] [--msfvenom ]  
               [--compiler pyinstaller] [--clean] [--ordnance-payload PAYLOAD]  
               [--list-encoders] [-e ENCODER] [-b \x00\x0a..] [--print-stats]  
  
Veil is a framework containing multiple tools.  
  
[*] Veil Options:  
  --list-tools          List Veil''s tools  
  -t TOOL, --tool TOOL  Specify Veil tool to use (Evasion, Ordnance etc.)  
  --update              Update the Veil framework  
  --setup               Run the Veil framework setup file & regenerate the  
                        configuration  
  --config              Regenerate the Veil framework configuration file  
  --version             Displays version and quits  
  
[*] Callback Settings:  
  --ip IP, --domain IP  IP address to connect back to  
  --port PORT           Port number to connect to  
  
[*] Payload Settings:  
  --list-payloads       Lists all available payloads for that tool  
  
[*] Veil-Evasion Options:  
  -p [PAYLOAD]          Payload to generate  
  -o OUTPUT-NAME        Output file base name for source and compiled binaries  
  -c [OPTION=value [OPTION=value ...]]  
                        Custom payload module options  
  --msfoptions [OPTION=value [OPTION=value ...]]  
                        Options for the specified metasploit payload  
  --msfvenom []         Metasploit shellcode to generate (e.g.  
                        windows/meterpreter/reverse_tcp etc.)  
  --compiler pyinstaller  
                        Compiler option for payload (currently only needed for  
                        Python)  
  --clean               Clean out payload folders  
  
[*] Veil-Ordnance Shellcode Options:  
  --ordnance-payload PAYLOAD  
                        Payload type (bind_tcp, rev_tcp, etc.)  
  
[*] Veil-Ordnance Encoder Options:  
  --list-encoders       Lists all available encoders  
  -e ENCODER, --encoder ENCODER  
                        Name of shellcode encoder to use  
  -b \x00\x0a.., --bad-chars \x00\x0a..  
                        Bad characters to avoid  
  --print-stats         Print information about the encoded shellcode
```

#### Veil Evasion CLI
```bash
$ ./Veil.py -t Evasion -p go/meterpreter/rev_tcp.py --ip 127.0.0.1 --port 4444  
===============================================================================  
                                   Veil-Evasion  
===============================================================================  
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework  
===============================================================================  
  
runtime/internal/sys  
runtime/internal/atomic  
runtime  
errors  
internal/race  
sync/atomic  
math  
sync  
io  
unicode/utf8  
internal/syscall/windows/sysdll  
unicode/utf16  
syscall  
strconv  
reflect  
encoding/binary  
command-line-arguments  
===============================================================================  
                                   Veil-Evasion  
===============================================================================  
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework  
===============================================================================  
  
 [*] Language: go  
 [*] Payload Module: go/meterpreter/rev_tcp  
 [*] Executable written to: /var/lib/veil/output/compiled/payload.exe  
 [*] Source code written to: /var/lib/veil/output/source/payload.go  
 [*] Metasploit Resource file written to: /var/lib/veil/output/handlers/payload.rc  
$  
$ file /var/lib/veil/output/compiled/payload.exe  
/var/lib/veil/output/compiled/payload.exe: PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows
```

#### Veil Ordnance CLI
```bash
$ ./Veil.py -t Ordnance --ordnance-payload rev_tcp --ip 127.0.0.1 --port 4444  
===============================================================================  
                                   Veil-Ordnance  
===============================================================================  
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework  
===============================================================================  
  
 [*] Payload Name: Reverse TCP Stager (Stage 1)  
 [*] IP Address: 127.0.0.1  
 [*] Port: 4444  
 [*] Shellcode Size: 287  
  
\xfc\xe8\x86\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\....
```


# PW Attacks

## Hydra
Network Service attack tool  
  
Usage Ex:  
```bash
# http
hydra 192.168.180.10 http-form-post "/form /frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f

# http-get
# add -t 1 to attempt to bypass account lockout
hydra -I -l user -P /usr/share/wordlists/rockyou.txt -t 1 "http-get://192.168.227.201:80/:A=BASIC:F=401"

# ftp
hydra ftp://192.168.241.202 -l <user> -P /usr/share/wordlists/rockyou.txt

# ssh
hydra ssh://192.168.241.202 -l <user> -P /usr/share/wordlists/rockyou.txt
```

| Options             | Desc                                                               |
| ------------------- | ------------------------------------------------------------------ |
| -R                  | restore a previous aborted/crashed session                         |
| -I                  | ignore an existing restore file (don't wait 10 seconds)            |
| -S                  | perform an SSL connect                                             |
| -s PORT             | if the service is on a different default port, define it here      |
| -l LOGIN or -L FILE | login with LOGIN name, or load several logins from FILE            |
| -p PASS  or -P FILE | try password PASS, or load several passwords from FILE             |
| -x MIN:MAX:CHARSET  | password bruteforce generation, type "-x -h" to get help           |
| -y                  | disable use of symbols in bruteforce, see above                    |
| -r                  | use a non-random shuffling method for option -x                    |
| -e nsr              | try "n" null password, "s" login as pass and/or "r" reversed login |
| -u                  | loop around users, not passwords (effective! implied with -x)      |
| -C FILE             | colon separated "login:pass" format, instead of -L/-P options      |
| -M FILE             | list of servers to attack, one entry per line, ':' to specify port |
| -o FILE             | write found login/password pairs to FILE instead of stdout         |
| -b FORMAT           | specify the format for the -o FILE: text(default), json, jsonv1    |
| -f / -F             | exit when a login/pass pair is found (-M: -f per host, -F global)  |
| -t TASKS            | run TASKS number of connects in parallel per target (default: 16)  |
| -T TASKS            | run TASKS connects in parallel overall (for -M, default: 64)       |
| -w / -W TIME        | wait time for a response (32) / between connects per thread (0)    |
| -c TIME             | wait time per login attempt over all threads (enforces -t 1)       |
| -4 / -6             | use IPv4 (default) / IPv6 addresses (put always in [] also in -M)  |
| -v / -V / -d        | verbose mode / show login+pass for each attempt / debug mode       |
| -O                  | use old SSL v2 and v3                                              |
| -K                  | do not redo failed attempts (good for -M mass scanning)            |
| -q                  | do not print messages about connection errors                      |
| -U                  | service module usage details                                       |
| -m OPT              | options specific for a module, see -U output for information       |
| -h                  | more command line options (COMPLETE HELP)                          |
| server              | the target: DNS, IP or 192.168.0.0/24 (this OR the -M option)      |
| service             | the service to crack (see below for supported protocols)           |
| OPT                 | some service modules support additional input (-U for module help) |

#### Supported services

adam6500, asterisk, cisco, cisco-enable, cobaltstrike, cvs, firebird, ftp\[s], http\[s]-{head|get|post}, http\[s]-{get|post}-form, http-proxy, http-proxy-urlenum,  
icq, imap\[s], irc, ldap2\[s], ldap3\[-{cram|digest}, md5]\[s], memcached, mongodb, mssql, mysql, nntp, oracle-listener, oracle-sid, pcanywhere, pcnfs, pop3\[s],  
postgres, radmin2, rdp, redis, rexec, rlogin, rpcap, rsh, rtsp, s7-300, sip, smb, smtp\[s], smtp-enum, snmp, socks5, ssh, sshkey, svn, teamspeak, telnet\[s], vmauthd, vnc, xmpp

#### To view info about a service's required args
```bash
hydra <service> -U
```


## Hashcat
https://hashcat.net

PW cracking tool.  
  
**Uses GPU for cracking rather than CPU (john)  

Combinator:
```bash
cewl www.megacorpone.com -m 12 -w cewl-megacorp.txt  
crunch 3 3 %%% > numbers.txt  
hashcat –m 1400 –a 1 flag.hash cewl-megacorp.txt numbers.txt
```

Usage:
```bash
hashcat [options]... hash|hashfile|hccapxfile [dictionary|mask|directory]...
```

### Options

|                               | Options Short / Long | Type                                                 | Description                          | Example |
| ----------------------------- | -------------------- | ---------------------------------------------------- | ------------------------------------ | ------- |
| -m, --hash-type               | Num                  | Hash-type, see references below                      | -m 1000                              |         |
| -a, --attack-mode             | Num                  | Attack-mode, see references below                    | -a 3                                 |         |
| -V, --version                 |                      | Print version                                        |                                      |         |
| -h, --help                    |                      | Print help                                           |                                      |         |
| --quiet                       |                      | Suppress output                                      |                                      |         |
| --hex-charset                 |                      | Assume charset is given in hex                       |                                      |         |
| --hex-salt                    |                      | Assume salt is given in hex                          |                                      |         |
| --hex-wordlist                |                      | Assume words in wordlist are given in hex            |                                      |         |
| --force                       |                      | Ignore warnings                                      |                                      |         |
| --status                      |                      | Enable automatic update of the status screen         |                                      |         |
| --status-json                 |                      | Enable JSON format for status output                 |                                      |         |
| --status-timer                | Num                  | Sets seconds between status screen updates to X      | --status-timer=1                     |         |
| --stdin-timeout-abort         | Num                  | Abort if there is no input from stdin for X seconds  | --stdin-timeout-abort=300            |         |
| --machine-readable            |                      | Display the status view in a machine-readable format |                                      |         |
| --keep-guessing               |                      | Keep guessing the hash after it has been cracked     |                                      |         |
| --self-test-disable           |                      | Disable self-test functionality on startup           |                                      |         |
| --loopback                    |                      | Add new plains to induct directory                   |                                      |         |
| --markov-hcstat2              | File                 | Specify hcstat2 file to use                          | --markov-hcstat2=my.hcstat2          |         |
| --markov-disable              |                      | Disables markov-chains, emulates classic brute-force |                                      |         |
| --markov-classic              |                      | Enables classic markov-chains, no per-position       |                                      |         |
| -t, --markov-threshold        | Num                  | Threshold X when to stop accepting new markov-chains | -t 50                                |         |
| --runtime                     | Num                  | Abort session after X seconds of runtime             | --runtime=10                         |         |
| --session                     | Str                  | Define specific session name                         | --session=mysession                  |         |
| --restore                     |                      | Restore session from --session                       |                                      |         |
| --restore-disable             |                      | Do not write restore file                            |                                      |         |
| --restore-file-path           | File                 | Specific path to restore file                        | --restore-file-path=x.restore        |         |
| -o, --outfile                 | File                 | Define outfile for recovered hash                    | -o outfile.txt                       |         |
| --outfile-format              | Str                  | Outfile format to use, separated with commas         | --outfile-format=1,3                 |         |
| --outfile-autohex-disable     |                      | Disable the use of $HEX[] in output plains           |                                      |         |
| --outfile-check-timer         | Num                  | Sets seconds between outfile checks to X             | --outfile-check=30                   |         |
| --wordlist-autohex-disable    |                      | Disable the conversion of $HEX[] from the wordlist   |                                      |         |
| -p, --separator               | Char                 | Separator char for hashlists and outfile             | -p :                                 |         |
| --stdout                      |                      | Do not crack a hash, instead print candidates only   |                                      |         |
| --show                        |                      | Compare hashlist with potfile; show cracked hashes   |                                      |         |
| --left                        |                      | Compare hashlist with potfile; show uncracked hashes |                                      |         |
| --username                    |                      | Enable ignoring of usernames in hashfile             |                                      |         |
| --remove                      |                      | Enable removal of hashes once they are cracked       |                                      |         |
| --remove-timer                | Num                  | Update input hash file each X seconds                | --remove-timer=30                    |         |
| --potfile-disable             |                      | Do not write potfile                                 |                                      |         |
| --potfile-path                | File                 | Specific path to potfile                             | --potfile-path=my.pot                |         |
| --encoding-from               | Code                 | Force internal wordlist encoding from X              | --encoding-from=iso-8859-15          |         |
| --encoding-to                 | Code                 | Force internal wordlist encoding to X                | --encoding-to=utf-32le               |         |
| --debug-mode                  | Num                  | Defines the debug mode (hybrid only by using rules)  | --debug-mode=4                       |         |
| --debug-file                  | File                 | Output file for debugging rules                      | --debug-file=good.log                |         |
| --induction-dir               | Dir                  | Specify the induction directory to use for loopback  | --induction=inducts                  |         |
| --outfile-check-dir           | Dir                  | Specify the outfile directory to monitor for plains  | --outfile-check-dir=x                |         |
| --logfile-disable             |                      | Disable the logfile                                  |                                      |         |
| --hccapx-message-pair         | Num                  | Load only message pairs from hccapx matching X       | --hccapx-message-pair=2              |         |
| --nonce-error-corrections     | Num                  | The BF size range to replace AP's nonce last bytes   | --nonce-error-corrections=16         |         |
| --keyboard-layout-mapping     | File                 | Keyboard layout mapping table for special hash-modes | --keyb=german.hckmap                 |         |
| --truecrypt-keyfiles          | File                 | Keyfiles to use, separated with commas               | --truecrypt-keyf=x.png               |         |
| --veracrypt-keyfiles          | File                 | Keyfiles to use, separated with commas               | --veracrypt-keyf=x.txt               |         |
| --veracrypt-pim-start         | Num                  | VeraCrypt personal iterations multiplier start       | --veracrypt-pim-start=450            |         |
| --veracrypt-pim-stop          | Num                  | VeraCrypt personal iterations multiplier stop        | --veracrypt-pim-stop=500             |         |
| -b, --benchmark               |                      | Run benchmark of selected hash-modes                 |                                      |         |
| --benchmark-all               |                      | Run benchmark of all hash-modes (requires -b)        |                                      |         |
| --speed-only                  |                      | Return expected speed of the attack, then quit       |                                      |         |
| --progress-only               |                      | Return ideal progress step size and time to process  |                                      |         |
| -c, --segment-size            | Num                  | Sets size in MB to cache from the wordfile to X      | -c 32                                |         |
| --bitmap-min                  | Num                  | Sets minimum bits allowed for bitmaps to X           | --bitmap-min=24                      |         |
| --bitmap-max                  | Num                  | Sets maximum bits allowed for bitmaps to X           | --bitmap-max=24                      |         |
| --cpu-affinity                | Str                  | Locks to CPU devices, separated with commas          | --cpu-affinity=1,2,3                 |         |
| --hook-threads                | Num                  | Sets number of threads for a hook (per compute unit) | --hook-threads=8                     |         |
| --example-hashes              |                      | Show an example hash for each hash-mode              |                                      |         |
| --backend-ignore-cuda         |                      | Do not try to open CUDA interface on startup         |                                      |         |
| --backend-ignore-opencl       |                      | Do not try to open OpenCL interface on startup       |                                      |         |
| -I, --backend-info            |                      | Show info about detected backend API devices         | -I                                   |         |
| -d, --backend-devices         | Str                  | Backend devices to use, separated with commas        | -d 1                                 |         |
| -D, --opencl-device-types     | Str                  | OpenCL device-types to use, separated with commas    | -D 1                                 |         |
| -O, --optimized-kernel-enable |                      | Enable optimized kernels (limits password length)    |                                      |         |
| -w, --workload-profile        | Num                  | Enable a specific workload profile, see pool below   | -w 3                                 |         |
| -n, --kernel-accel            | Num                  | Manual workload tuning, set outerloop step size to X | -n 64                                |         |
| -u, --kernel-loops            | Num                  | Manual workload tuning, set innerloop step size to X | -u 256                               |         |
| -T, --kernel-threads          | Num                  | Manual workload tuning, set thread count to X        | -T 64                                |         |
| --backend-vector-width        | Num                  | Manually override backend vector-width to X          | --backend-vector=4                   |         |
| --spin-damp                   | Num                  | Use CPU for device synchronization, in percent       | --spin-damp=10                       |         |
| --hwmon-disable               |                      | Disable temperature and fanspeed reads and triggers  |                                      |         |
| --hwmon-temp-abort            | Num                  | Abort if temperature reaches X degrees Celsius       | --hwmon-temp-abort=100               |         |
| --scrypt-tmto                 | Num                  | Manually override TMTO value for scrypt to X         | --scrypt-tmto=3                      |         |
| -s, --skip                    | Num                  | Skip X words from the start                          | -s 1000000                           |         |
| -l, --limit                   | Num                  | Limit X words from the start + skipped words         | -l 1000000                           |         |
| --keyspace                    |                      | Show keyspace base:mod values and quit               |                                      |         |
| -j, --rule-left               | Rule                 | Single rule applied to each word from left wordlist  | -j 'c'                               |         |
| -k, --rule-right              | Rule                 | Single rule applied to each word from right wordlist | -k '^-'                              |         |
| -r, --rules-file              | File                 | Multiple rules applied to each word from wordlists   | -r rules/best64.rule                 |         |
| -g, --generate-rules          | Num                  | Generate X random rules                              | -g 10000                             |         |
| --generate-rules-func-min     | Num                  | Force min X functions per rule                       |                                      |         |
| --generate-rules-func-max     | Num                  | Force max X functions per rule                       |                                      |         |
| --generate-rules-seed         | Num                  | Force RNG seed set to X                              |                                      |         |
| -1, --custom-charset1         | CS                   | User-defined charset ?1                              | -1 ?l?d?u                            |         |
| -2, --custom-charset2         | CS                   | User-defined charset ?2                              | -2 ?l?d?s                            |         |
| -3, --custom-charset3         | CS                   | User-defined charset ?3                              |                                      |         |
| -4, --custom-charset4         | CS                   | User-defined charset ?4                              |                                      |         |
| -i, --increment               |                      | Enable mask increment mode                           |                                      |         |
| --increment-min               | Num                  | Start mask incrementing at X                         | --increment-min=4                    |         |
| --increment-max               | Num                  | Stop mask incrementing at X                          | --increment-max=8                    |         |
| -S, --slow-candidates         |                      | Enable slower (but advanced) candidate generators    |                                      |         |
| --brain-server                |                      | Enable brain server                                  |                                      |         |
| --brain-server-timer          | Num                  | Update the brain server dump each X seconds (min:60) | --brain-server-timer=300             |         |
| -z, --brain-client            |                      | Enable brain client, activates -S                    |                                      |         |
| --brain-client-features       | Num                  | Define brain client features, see below              | --brain-client-features=3            |         |
| --brain-host                  | Str                  | Brain server host (IP or domain)                     | --brain-host=127.0.0.1               |         |
| --brain-port                  | Port                 | Brain server port                                    | --brain-port=13743                   |         |
| --brain-password              | Str                  | Brain server authentication password                 | --brain-password=bZfhCvGUSjRq        |         |
| --brain-session               | Hex                  | Overrides automatically calculated brain session     | --brain-session=0x2ae611db           |         |
| --brain-session-whitelist     | Hex                  | Allow given sessions only, separated with commas     | --brain-session-whitelist=0x2ae611db |         |

### Hash modes

| Name  | Category                                         |                                       |
| ----- | ------------------------------------------------ | ------------------------------------- |
| 900   | MD4                                              | Raw Hash                              |
| 0     | MD5                                              | Raw Hash                              |
| 100   | SHA1                                             | Raw Hash                              |
| 1300  | SHA2-224                                         | Raw Hash                              |
| 1400  | SHA2-256                                         | Raw Hash                              |
| 10800 | SHA2-384                                         | Raw Hash                              |
| 1700  | SHA2-512                                         | Raw Hash                              |
| 17300 | SHA3-224                                         | Raw Hash                              |
| 17400 | SHA3-256                                         | Raw Hash                              |
| 17500 | SHA3-384                                         | Raw Hash                              |
| 17600 | SHA3-512                                         | Raw Hash                              |
| 6000  | RIPEMD-160                                       | Raw Hash                              |
| 600   | BLAKE2b-512                                      | Raw Hash                              |
| 11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian | Raw Hash                              |
| 11800 | GOST R 34.11-2012 (Streebog) 512-bit, big-endian | Raw Hash                              |
| 6900  | GOST R 34.11-94                                  | Raw Hash                              |
| 5100  | Half MD5                                         | Raw Hash                              |
| 18700 | Java Object hashCode()                           | Raw Hash                              |
| 17700 | Keccak-224                                       | Raw Hash                              |
| 17800 | Keccak-256                                       | Raw Hash                              |
| 17900 | Keccak-384                                       | Raw Hash                              |
| 18000 | Keccak-512                                       | Raw Hash                              |
| 21400 | sha256(sha256_bin($pass))                        | Raw Hash                              |
| 6100  | Whirlpool                                        | Raw Hash                              |
| 10100 | SipHash                                          | Raw Hash                              |
| 21000 | BitShares v0.x - sha512(sha512_bin(pass))        | Raw Hash                              |
| 10    | md5($pass.$salt)                                 | Raw Hash, Salted and/or Iterated      |
| 20    | md5($salt.$pass)                                 | Raw Hash, Salted and/or Iterated      |
| 3800  | md5($salt.$pass.$salt)                           | Raw Hash, Salted and/or Iterated      |
| 3710  | md5($salt.md5($pass))                            | Raw Hash, Salted and/or Iterated      |
| 4110  | md5($salt.md5($pass.$salt))                      | Raw Hash, Salted and/or Iterated      |
| 4010  | md5($salt.md5($salt.$pass))                      | Raw Hash, Salted and/or Iterated      |
| 21300 | md5($salt.sha1($salt.$pass))                     | Raw Hash, Salted and/or Iterated      |
| 40    | md5($salt.utf16le($pass))                        | Raw Hash, Salted and/or Iterated      |
| 2600  | md5(md5($pass))                                  | Raw Hash, Salted and/or Iterated      |
| 3910  | md5(md5($pass).md5($salt))                       | Raw Hash, Salted and/or Iterated      |
| 4400  | md5(sha1($pass))                                 | Raw Hash, Salted and/or Iterated      |
| 20900 | md5(sha1($pass).md5($pass).sha1($pass))          | Raw Hash, Salted and/or Iterated      |
| 21200 | md5(sha1($salt).md5($pass))                      | Raw Hash, Salted and/or Iterated      |
| 4300  | md5(strtoupper(md5($pass)))                      | Raw Hash, Salted and/or Iterated      |
| 30    | md5(utf16le($pass).$salt)                        | Raw Hash, Salted and/or Iterated      |
| 110   | sha1($pass.$salt)                                | Raw Hash, Salted and/or Iterated      |
| 120   | sha1($salt.$pass)                                | Raw Hash, Salted and/or Iterated      |
| 4900  | sha1($salt.$pass.$salt)                          | Raw Hash, Salted and/or Iterated      |
| 4520  | sha1($salt.sha1($pass))                          | Raw Hash, Salted and/or Iterated      |
| 140   | sha1($salt.utf16le($pass))                       | Raw Hash, Salted and/or Iterated      |
| 19300 | sha1($salt1.$pass.$salt2)                        | Raw Hash, Salted and/or Iterated      |
| 14400 | sha1(CX)                                         | Raw Hash, Salted and/or Iterated      |
| 4700  | sha1(md5($pass))                                 | Raw Hash, Salted and/or Iterated      |
| 4710  | sha1(md5($pass).$salt)                           | Raw Hash, Salted and/or Iterated      |
| 21100 | sha1(md5($pass.$salt))                           | Raw Hash, Salted and/or Iterated      |
| 18500 | sha1(md5(md5($pass)))                            | Raw Hash, Salted and/or Iterated      |
| 4500  | sha1(sha1($pass))                                | Raw Hash, Salted and/or Iterated      |
| 130   | sha1(utf16le($pass).$salt)                       | Raw Hash, Salted and/or Iterated      |
| 1410  | sha256($pass.$salt)                              | Raw Hash, Salted and/or Iterated      |
| 1420  | sha256($salt.$pass)                              | Raw Hash, Salted and/or Iterated      |
| 22300 | sha256($salt.$pass.$salt)                        | Raw Hash, Salted and/or Iterated      |
| 1440  | sha256($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated      |
| 20800 | sha256(md5($pass))                               | Raw Hash, Salted and/or Iterated      |
| 20710 | sha256(sha256($pass).$salt)                      | Raw Hash, Salted and/or Iterated      |
| 1430  | sha256(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated      |
| 1710  | sha512($pass.$salt)                              | Raw Hash, Salted and/or Iterated      |
| 1720  | sha512($salt.$pass)                              | Raw Hash, Salted and/or Iterated      |
| 1740  | sha512($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated      |
| 1730  | sha512(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated      |
| 19500 | Ruby on Rails Restful-Authentication             | Raw Hash, Salted and/or Iterated      |
| 50    | HMAC-MD5 (key = $pass)                           | Raw Hash, Authenticated               |
| 60    | HMAC-MD5 (key = $salt)                           | Raw Hash, Authenticated               |
| 150   | HMAC-SHA1 (key = $pass)                          | Raw Hash, Authenticated               |
| 160   | HMAC-SHA1 (key = $salt)                          | Raw Hash, Authenticated               |
| 1450  | HMAC-SHA256 (key = $pass)                        | Raw Hash, Authenticated               |
| 1460  | HMAC-SHA256 (key = $salt)                        | Raw Hash, Authenticated               |
| 1750  | HMAC-SHA512 (key = $pass)                        | Raw Hash, Authenticated               |
| 1760  | HMAC-SHA512 (key = $salt)                        | Raw Hash, Authenticated               |
| 11750 | HMAC-Streebog-256 (key = $pass), big-endian      | Raw Hash, Authenticated               |
| 11760 | HMAC-Streebog-256 (key = $salt), big-endian      | Raw Hash, Authenticated               |
| 11850 | HMAC-Streebog-512 (key = $pass), big-endian      | Raw Hash, Authenticated               |
| 11860 | HMAC-Streebog-512 (key = $salt), big-endian      | Raw Hash, Authenticated               |
| 11500 | CRC32                                            | Raw Checksum                          |
| 14100 | 3DES (PT = $salt, key = $pass)                   | Raw Cipher, Known-Plaintext attack    |
| 14000 | DES (PT = $salt, key = $pass)                    | Raw Cipher, Known-Plaintext attack    |
| 15400 | ChaCha20                                         | Raw Cipher, Known-Plaintext attack    |
| 14900 | Skip32 (PT = $salt, key = $pass)                 | Raw Cipher, Known-Plaintext attack    |
| 11900 | PBKDF2-HMAC-MD5                                  | Generic KDF                           |
| 12000 | PBKDF2-HMAC-SHA1                                 | Generic KDF                           |
| 10900 | PBKDF2-HMAC-SHA256                               | Generic KDF                           |
| 12100 | PBKDF2-HMAC-SHA512                               | Generic KDF                           |
| 8900  | scrypt                                           | Generic KDF                           |
| 400   | phpass                                           | Generic KDF                           |
| 16900 | Ansible Vault                                    | Generic KDF                           |
| 12001 | Atlassian (PBKDF2-HMAC-SHA1)                     | Generic KDF                           |
| 20200 | Python passlib pbkdf2-sha512                     | Generic KDF                           |
| 20300 | Python passlib pbkdf2-sha256                     | Generic KDF                           |
| 20400 | Python passlib pbkdf2-sha1                       | Generic KDF                           |
| 16100 | TACACS+                                          | Network Protocols                     |
| 11400 | SIP digest authentication (MD5)                  | Network Protocols                     |
| 5300  | IKE-PSK MD5                                      | Network Protocols                     |
| 5400  | IKE-PSK SHA1                                     | Network Protocols                     |
| 23200 | XMPP SCRAM PBKDF2-SHA1                           | Network Protocols                     |
| 2500  | WPA-EAPOL-PBKDF2                                 | Network Protocols                     |
| 2501  | WPA-EAPOL-PMK                                    | Network Protocols                     |
| 22000 | WPA-PBKDF2-PMKID+EAPOL                           | Network Protocols                     |
| 22001 | WPA-PMK-PMKID+EAPOL                              | Network Protocols                     |
| 16800 | WPA-PMKID-PBKDF2                                 | Network Protocols                     |
| 16801 | WPA-PMKID-PMK                                    | Network Protocols                     |
| 7300  | IPMI2 RAKP HMAC-SHA1                             | Network Protocols                     |
| 10200 | CRAM-MD5                                         | Network Protocols                     |
| 4800  | iSCSI CHAP authentication, MD5(CHAP)             | Network Protocols                     |
| 16500 | JWT (JSON Web Token)                             | Network Protocols                     |
| 22600 | Telegram Desktop App Passcode (PBKDF2-HMAC-SHA1) | Network Protocols                     |
| 22301 | Telegram Mobile App Passcode (SHA256)            | Network Protocols                     |
| 7500  | Kerberos 5, etype 23, AS-REQ Pre-Auth            | Network Protocols                     |
| 13100 | Kerberos 5, etype 23, TGS-REP                    | Network Protocols                     |
| 18200 | Kerberos 5, etype 23, AS-REP                     | Network Protocols                     |
| 19600 | Kerberos 5, etype 17, TGS-REP                    | Network Protocols                     |
| 19700 | Kerberos 5, etype 18, TGS-REP                    | Network Protocols                     |
| 19800 | Kerberos 5, etype 17, Pre-Auth                   | Network Protocols                     |
| 19900 | Kerberos 5, etype 18, Pre-Auth                   | Network Protocols                     |
| 5500  | NetNTLMv1 / NetNTLMv1+ESS                        | Network Protocols                     |
| 5600  | NetNTLMv2                                        | Network Protocols                     |
| 23    | Skype                                            | Network Protocols                     |
| 11100 | PostgreSQL CRAM (MD5)                            | Network Protocols                     |
| 11200 | MySQL CRAM (SHA1)                                | Network Protocols                     |
| 8500  | RACF                                             | Operating System                      |
| 6300  | AIX {smd5}                                       | Operating System                      |
| 6700  | AIX {ssha1}                                      | Operating System                      |
| 6400  | AIX {ssha256}                                    | Operating System                      |
| 6500  | AIX {ssha512}                                    | Operating System                      |
| 3000  | LM                                               | Operating System                      |
| 19000 | QNX /etc/shadow (MD5)                            | Operating System                      |
| 19100 | QNX /etc/shadow (SHA256)                         | Operating System                      |
| 19200 | QNX /etc/shadow (SHA512)                         | Operating System                      |
| 15300 | DPAPI masterkey file v1                          | Operating System                      |
| 15900 | DPAPI masterkey file v2                          | Operating System                      |
| 7200  | GRUB 2                                           | Operating System                      |
| 12800 | MS-AzureSync PBKDF2-HMAC-SHA256                  | Operating System                      |
| 12400 | BSDi Crypt, Extended DES                         | Operating System                      |
| 1000  | NTLM                                             | Operating System                      |
| 122   | macOS v10.4, macOS v10.5, MacOS v10.6            | Operating System                      |
| 1722  | macOS v10.7                                      | Operating System                      |
| 7100  | macOS v10.8+ (PBKDF2-SHA512)                     | Operating System                      |
| 9900  | Radmin2                                          | Operating System                      |
| 5800  | Samsung Android Password/PIN                     | Operating System                      |
| 3200  | bcrypt $2*$, Blowfish (Unix)                     | Operating System                      |
| 500   | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)        | Operating System                      |
| 1500  | descrypt, DES (Unix), Traditional DES            | Operating System                      |
| 7400  | sha256crypt $5$, SHA256 (Unix)                   | Operating System                      |
| 1800  | sha512crypt $6$, SHA512 (Unix)                   | Operating System                      |
| 13800 | Windows Phone 8+ PIN/password                    | Operating System                      |
| 2410  | Cisco-ASA MD5                                    | Operating System                      |
| 9200  | Cisco-IOS $8$ (PBKDF2-SHA256)                    | Operating System                      |
| 9300  | Cisco-IOS $9$ (scrypt)                           | Operating System                      |
| 5700  | Cisco-IOS type 4 (SHA256)                        | Operating System                      |
| 2400  | Cisco-PIX MD5                                    | Operating System                      |
| 8100  | Citrix NetScaler (SHA1)                          | Operating System                      |
| 22200 | Citrix NetScaler (SHA512)                        | Operating System                      |
| 1100  | Domain Cached Credentials (DCC), MS Cache        | Operating System                      |
| 2100  | Domain Cached Credentials 2 (DCC2), MS Cache 2   | Operating System                      |
| 7000  | FortiGate (FortiOS)                              | Operating System                      |
| 125   | ArubaOS                                          | Operating System                      |
| 501   | Juniper IVE                                      | Operating System                      |
| 22    | Juniper NetScreen/SSG (ScreenOS)                 | Operating System                      |
| 15100 | Juniper/NetBSD sha1crypt                         | Operating System                      |
| 131   | MSSQL (2000)                                     | Database Server                       |
| 132   | MSSQL (2005)                                     | Database Server                       |
| 1731  | MSSQL (2012, 2014)                               | Database Server                       |
| 12    | PostgreSQL                                       | Database Server                       |
| 3100  | Oracle H: Type (Oracle 7+)                       | Database Server                       |
| 112   | Oracle S: Type (Oracle 11+)                      | Database Server                       |
| 12300 | Oracle T: Type (Oracle 12+)                      | Database Server                       |
| 7401  | MySQL $A$ (sha256crypt)                          | Database Server                       |
| 200   | MySQL323                                         | Database Server                       |
| 300   | MySQL4.1/MySQL5                                  | Database Server                       |
| 8000  | Sybase ASE                                       | Database Server                       |
| 1421  | hMailServer                                      | FTP, HTTP, SMTP, LDAP Server          |
| 8300  | DNSSEC (NSEC3)                                   | FTP, HTTP, SMTP, LDAP Server          |
| 16400 | CRAM-MD5 Dovecot                                 | FTP, HTTP, SMTP, LDAP Server          |
| 1411  | SSHA-256(Base64), LDAP {SSHA256}                 | FTP, HTTP, SMTP, LDAP Server          |
| 1711  | SSHA-512(Base64), LDAP {SSHA512}                 | FTP, HTTP, SMTP, LDAP Server          |
| 10901 | RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)          | FTP, HTTP, SMTP, LDAP Server          |
| 15000 | FileZilla Server >= 0.9.55                       | FTP, HTTP, SMTP, LDAP Server          |
| 12600 | ColdFusion 10+                                   | FTP, HTTP, SMTP, LDAP Server          |
| 1600  | Apache $apr1$ MD5, md5apr1, MD5 (APR)            | FTP, HTTP, SMTP, LDAP Server          |
| 141   | Episerver 6.x < .NET 4                           | FTP, HTTP, SMTP, LDAP Server          |
| 1441  | Episerver 6.x >= .NET 4                          | FTP, HTTP, SMTP, LDAP Server          |
| 101   | nsldap, SHA-1(Base64), Netscape LDAP SHA         | FTP, HTTP, SMTP, LDAP Server          |
| 111   | nsldaps, SSHA-1(Base64), Netscape LDAP SSHA      | FTP, HTTP, SMTP, LDAP Server          |
| 7700  | SAP CODVN B (BCODE)                              | Enterprise Application Software (EAS) |
| 7701  | SAP CODVN B (BCODE) from RFC_READ_TABLE          | Enterprise Application Software (EAS) |
| 7800  | SAP CODVN F/G (PASSCODE)                         | Enterprise Application Software (EAS) |
| 7801  | SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE     | Enterprise Application Software (EAS) |
| 10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1              | Enterprise Application Software (EAS) |
| 133   | PeopleSoft                                       | Enterprise Application Software (EAS) |
| 13500 | PeopleSoft PS_TOKEN                              | Enterprise Application Software (EAS) |
| 21500 | SolarWinds Orion                                 | Enterprise Application Software (EAS) |
| 8600  | Lotus Notes/Domino 5                             | Enterprise Application Software (EAS) |
| 8700  | Lotus Notes/Domino 6                             | Enterprise Application Software (EAS) |
| 9100  | Lotus Notes/Domino 8                             | Enterprise Application Software (EAS) |
| 20600 | Oracle Transportation Management (SHA256)        | Enterprise Application Software (EAS) |
| 4711  | Huawei sha1(md5($pass).$salt)                    | Enterprise Application Software (EAS) |
| 20711 | AuthMe sha256                                    | Enterprise Application Software (EAS) |
| 12200 | eCryptfs                                         | Full-Disk Encryption (FDE)            |
| 22400 | AES Crypt (SHA256)                               | Full-Disk Encryption (FDE)            |
| 14600 | LUKS                                             | Full-Disk Encryption (FDE)            |
| 13711 | VeraCrypt RIPEMD160 + XTS 512 bit                | Full-Disk Encryption (FDE)            |
| 13712 | VeraCrypt RIPEMD160 + XTS 1024 bit               | Full-Disk Encryption (FDE)            |
| 13713 | VeraCrypt RIPEMD160 + XTS 1536 bit               | Full-Disk Encryption (FDE)            |
| 13741 | VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode    | Full-Disk Encryption (FDE)            |
| 13742 | VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode   | Full-Disk Encryption (FDE)            |
| 13743 | VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode   | Full-Disk Encryption (FDE)            |
| 13751 | VeraCrypt SHA256 + XTS 512 bit                   | Full-Disk Encryption (FDE)            |
| 13752 | VeraCrypt SHA256 + XTS 1024 bit                  | Full-Disk Encryption (FDE)            |
| 13753 | VeraCrypt SHA256 + XTS 1536 bit                  | Full-Disk Encryption (FDE)            |
| 13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode       | Full-Disk Encryption (FDE)            |
| 13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode      | Full-Disk Encryption (FDE)            |
| 13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode      | Full-Disk Encryption (FDE)            |
| 13721 | VeraCrypt SHA512 + XTS 512 bit                   | Full-Disk Encryption (FDE)            |
| 13722 | VeraCrypt SHA512 + XTS 1024 bit                  | Full-Disk Encryption (FDE)            |
| 13723 | VeraCrypt SHA512 + XTS 1536 bit                  | Full-Disk Encryption (FDE)            |
| 13771 | VeraCrypt Streebog-512 + XTS 512 bit             | Full-Disk Encryption (FDE)            |
| 13772 | VeraCrypt Streebog-512 + XTS 1024 bit            | Full-Disk Encryption (FDE)            |
| 13773 | VeraCrypt Streebog-512 + XTS 1536 bit            | Full-Disk Encryption (FDE)            |
| 13731 | VeraCrypt Whirlpool + XTS 512 bit                | Full-Disk Encryption (FDE)            |
| 13732 | VeraCrypt Whirlpool + XTS 1024 bit               | Full-Disk Encryption (FDE)            |
| 13733 | VeraCrypt Whirlpool + XTS 1536 bit               | Full-Disk Encryption (FDE)            |
| 16700 | FileVault 2                                      | Full-Disk Encryption (FDE)            |
| 20011 | DiskCryptor SHA512 + XTS 512 bit                 | Full-Disk Encryption (FDE)            |
| 20012 | DiskCryptor SHA512 + XTS 1024 bit                | Full-Disk Encryption (FDE)            |
| 20013 | DiskCryptor SHA512 + XTS 1536 bit                | Full-Disk Encryption (FDE)            |
| 22100 | BitLocker                                        | Full-Disk Encryption (FDE)            |
| 12900 | Android FDE (Samsung DEK)                        | Full-Disk Encryption (FDE)            |
| 8800  | Android FDE <= 4.3                               | Full-Disk Encryption (FDE)            |
| 18300 | Apple File System (APFS)                         | Full-Disk Encryption (FDE)            |
| 6211  | TrueCrypt RIPEMD160 + XTS 512 bit                | Full-Disk Encryption (FDE)            |
| 6212  | TrueCrypt RIPEMD160 + XTS 1024 bit               | Full-Disk Encryption (FDE)            |
| 6213  | TrueCrypt RIPEMD160 + XTS 1536 bit               | Full-Disk Encryption (FDE)            |
| 6241  | TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode    | Full-Disk Encryption (FDE)            |
| 6242  | TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode   | Full-Disk Encryption (FDE)            |
| 6243  | TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode   | Full-Disk Encryption (FDE)            |
| 6221  | TrueCrypt SHA512 + XTS 512 bit                   | Full-Disk Encryption (FDE)            |
| 6222  | TrueCrypt SHA512 + XTS 1024 bit                  | Full-Disk Encryption (FDE)            |
| 6223  | TrueCrypt SHA512 + XTS 1536 bit                  | Full-Disk Encryption (FDE)            |
| 6231  | TrueCrypt Whirlpool + XTS 512 bit                | Full-Disk Encryption (FDE)            |
| 6232  | TrueCrypt Whirlpool + XTS 1024 bit               | Full-Disk Encryption (FDE)            |
| 6233  | TrueCrypt Whirlpool + XTS 1536 bit               | Full-Disk Encryption (FDE)            |
| 10400 | PDF 1.1 - 1.3 (Acrobat 2 - 4)                    | Documents                             |
| 10410 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1       | Documents                             |
| 10420 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2       | Documents                             |
| 10500 | PDF 1.4 - 1.6 (Acrobat 5 - 8)                    | Documents                             |
| 10600 | PDF 1.7 Level 3 (Acrobat 9)                      | Documents                             |
| 10700 | PDF 1.7 Level 8 (Acrobat 10 - 11)                | Documents                             |
| 9400  | MS Office 2007                                   | Documents                             |
| 9500  | MS Office 2010                                   | Documents                             |
| 9600  | MS Office 2013                                   | Documents                             |
| 9700  | MS Office <= 2003 $0/$1, MD5 + RC4               | Documents                             |
| 9710  | MS Office <= 2003 $0/$1, MD5 + RC4, collider #1  | Documents                             |
| 9720  | MS Office <= 2003 $0/$1, MD5 + RC4, collider #2  | Documents                             |
| 9800  | MS Office <= 2003 $3/$4, SHA1 + RC4              | Documents                             |
| 9810  | MS Office <= 2003 $3, SHA1 + RC4, collider #1    | Documents                             |
| 9820  | MS Office <= 2003 $3, SHA1 + RC4, collider #2    | Documents                             |
| 18400 | Open Document Format (ODF) 1.2 (SHA-256, AES)    | Documents                             |
| 18600 | Open Document Format (ODF) 1.1 (SHA-1, Blowfish) | Documents                             |
| 16200 | Apple Secure Notes                               | Documents                             |
| 15500 | JKS Java Key Store Private Keys (SHA1)           | Password Managers                     |
| 6600  | 1Password, agilekeychain                         | Password Managers                     |
| 8200  | 1Password, cloudkeychain                         | Password Managers                     |
| 9000  | Password Safe v2                                 | Password Managers                     |
| 5200  | Password Safe v3                                 | Password Managers                     |
| 6800  | LastPass + LastPass sniffed                      | Password Managers                     |
| 13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)      | Password Managers                     |
| 11300 | Bitcoin/Litecoin wallet.dat                      | Password Managers                     |
| 16600 | Electrum Wallet (Salt-Type 1-3)                  | Password Managers                     |
| 21700 | Electrum Wallet (Salt-Type 4)                    | Password Managers                     |
| 21800 | Electrum Wallet (Salt-Type 5)                    | Password Managers                     |
| 12700 | Blockchain, My Wallet                            | Password Managers                     |
| 15200 | Blockchain, My Wallet, V2                        | Password Managers                     |
| 18800 | Blockchain, My Wallet, Second Password (SHA256)  | Password Managers                     |
| 23100 | Apple Keychain                                   | Password Managers                     |
| 16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256     | Password Managers                     |
| 15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256              | Password Managers                     |
| 15700 | Ethereum Wallet, SCRYPT                          | Password Managers                     |
| 22500 | MultiBit Classic .key (MD5)                      | Password Managers                     |
| 22700 | MultiBit HD (scrypt)                             | Password Managers                     |
| 11600 | 7-Zip                                            | Archives                              |
| 12500 | RAR3-hp                                          | Archives                              |
| 13000 | RAR5                                             | Archives                              |
| 17200 | PKZIP (Compressed)                               | Archives                              |
| 17220 | PKZIP (Compressed Multi-File)                    | Archives                              |
| 17225 | PKZIP (Mixed Multi-File)                         | Archives                              |
| 17230 | PKZIP (Mixed Multi-File Checksum-Only)           | Archives                              |
| 17210 | PKZIP (Uncompressed)                             | Archives                              |
| 20500 | PKZIP Master Key                                 | Archives                              |
| 20510 | PKZIP Master Key (6 byte optimization)           | Archives                              |
| 14700 | iTunes backup < 10.0                             | Archives                              |
| 14800 | iTunes backup >= 10.0                            | Archives                              |
| 23001 | SecureZIP AES-128                                | Archives                              |
| 23002 | SecureZIP AES-192                                | Archives                              |
| 23003 | SecureZIP AES-256                                | Archives                              |
| 13600 | WinZip                                           | Archives                              |
| 18900 | Android Backup                                   | Archives                              |
| 13200 | AxCrypt                                          | Archives                              |
| 13300 | AxCrypt in-memory SHA1                           | Archives                              |
| 8400  | WBB3 (Woltlab Burning Board)                     | Forums, CMS, E-Commerce               |
| 2611  | vBulletin < v3.8.5                               | Forums, CMS, E-Commerce               |
| 2711  | vBulletin >= v3.8.5                              | Forums, CMS, E-Commerce               |
| 2612  | PHPS                                             | Forums, CMS, E-Commerce               |
| 121   | SMF (Simple Machines Forum) > v1.1               | Forums, CMS, E-Commerce               |
| 3711  | MediaWiki B type                                 | Forums, CMS, E-Commerce               |
| 4521  | Redmine                                          | Forums, CMS, E-Commerce               |
| 11    | Joomla < 2.5.18                                  | Forums, CMS, E-Commerce               |
| 13900 | OpenCart                                         | Forums, CMS, E-Commerce               |
| 11000 | PrestaShop                                       | Forums, CMS, E-Commerce               |
| 16000 | Tripcode                                         | Forums, CMS, E-Commerce               |
| 7900  | Drupal7                                          | Forums, CMS, E-Commerce               |
| 21    | osCommerce, xt:Commerce                          | Forums, CMS, E-Commerce               |
| 4522  | PunBB                                            | Forums, CMS, E-Commerce               |
| 2811  | MyBB 1.2+, IPB2+ (Invision Power Board)          | Forums, CMS, E-Commerce               |
| 18100 | TOTP (HMAC-SHA1)                                 | One-Time Passwords                    |
| 2000  | STDOUT                                           | Plaintext                             |
| 99999 | Plaintext                                        | Plaintext                             |
| 21600 | Web2py pbkdf2-sha512                             | Framework                             |
| 10000 | Django (PBKDF2-SHA256)                           | Framework                             |
| 124   | Django (SHA-1)                                   | Framework                             |

### Brain Client Features

| # | Features |
| ---- | ---- |
|  1 | Send hashed passwords|
|  2 | Send attack positions|
|  3 | Send hashed passwords and attack positions|

### Outfile Formats

 | # | Format|
| ---- | ---- |
|  1 | hash[:salt]|
|  2 | plain|
|  3 | hex_plain|
|  4 | crack_pos|
|  5 | timestamp absolute|
|  6 | timestamp relative|

### Rule Debugging Modes
[Rule-based Attack Mutations](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

 | # | Format|
 | ---- | ---- |
|  1 | Finding-Rule|
|  2 | Original-Word|
|  3 | Original-Word:Finding-Rule|
|  4 | Original-Word:Finding-Rule:Processed-Word|

### Attack Modes

 | # | Mode|
 | ---- | ---- |
|  0 | Straight|
|  1 | Combination|
|  3 | Brute-force|
|  6 | Hybrid Wordlist + Mask|
|  7 | Hybrid Mask + Wordlist|

### Built-in Charsets 

 | ? | Charset|
 | ---- |----|
|  l | abcdefghijklmnopqrstuvwxyz|
|  u | ABCDEFGHIJKLMNOPQRSTUVWXYZ|
|  d | 0123456789|
|  h | 0123456789abcdef|
|  H | 0123456789ABCDEF|
|  s | !"#$%&'()\*+,-./:;<=>?@\[\\]^\_\`{\|}~|
|  a | ?l?u?d?s|
|  b | 0x00 - 0xff|

### OpenCL Device Types

 | # | Device Type|
 | ---- | ---- |
|  1 | CPU|
|  2 | GPU|
|  3 | FPGA, DSP, Co-Processor|

### Workload Profiles

 | # | Performance | Runtime | Power Consumption | Desktop Impact|
 | ---- | ---- |
|  1 | Low         |   2 ms  | Low               | Minimal|
|  2 | Default     |  12 ms  | Economic          | Noticeable|
|  3 | High        |  96 ms  | High              | Unresponsive|
|  4 | Nightmare   | 480 ms  | Insane            | Headless|

### Basic Examples

| Attack- Mode | Hash- Type | Example command|
| ---- | ---- | ---- |
|  Wordlist         | $P$   | hashcat -a 0 -m 400 example400.hash example.dict|
|  Wordlist + Rules | MD5   | hashcat -a 0 -m 0 example0.hash example.dict -r rules/best64.rule|
|  Brute-Force      | MD5   | hashcat -a 3 -m 0 example0.hash ?a?a?a?a?a?a|
|  Combinator       | MD5   | hashcat -a 1 -m 0 example0.hash example.dict example.dict|



## John the Ripper

Password cracker. Can also generate custom wordlists & apply rule permutations.  
**Speed is limited to the power of the CPUs dedicated to the task.  
  
Config file: /etc/john/john.conf  
  
To mutate a wordlist, navigate to **\[List.Rules:Wordlist]** segment, add section for your own rules ( **\[List.Rules:myrules]**)
  
  
Create hash file from .zip or .rar:  
```bash
zip2john flag.zip  
rar2john flag.rar
```

**NOTE:**  Hash syntax requirements:
	\<user>:\<hash>

Usage:  
```bash
john [ OPTIONS ] [ PASSWORD-FILES ]
```


Brute forcing:  
	Supply pw file (& hopefully format).  
	Can take a long time  
  
Wordlist:  
	**--wordlist**  
	Faster, but less coverage.  
  
Word mangling:  
	**--rules**  
	Recommend if any pw left after BF & Wordlist are exhausted.  
  
  
Linux:  
	Need to combine _/etc/passwd_ & _/etc/shadow_ fies w/ **unshadow**  
```bash
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
```

 
**--fork** & **--node** ex:  
- Assuming two machines, each with an 8-core CPU.  
	- 1st machine - **--fork=8** & **--node=1-8/16**:  
		- Creates eight processes on this machine  
		- Splits the supplied wordlist into sixteen equal parts  
		- Process the first eight parts locally.  
	- 2nd machine - **--fork=8** & **--node=9-16**:  
		- Assigns eight processes to the 2nd half of the wordlist.  

| Options                                   | Desc                                                                                                  |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| --help                                    | Print usage summary                                                                                   |
| --single\[=SECTION\[,..\]\]               | "Single crack" mode, using default or named rules                                                     |
| --single=:rule\[,..\]                     | Same, using "immediate" rule(s)                                                                       |
| --single-seed=WORD\[,WORD\]               | Add static seed word(s) for all salts in single mode                                                  |
| --single-wordlist=FILE                    | *Short* wordlist with static seed words/morphemes                                                     |
| --single-user-seed=FILE                   | Wordlist with seeds per username (user:password\[s\] format)                                          |
| --single-pair-max=N                       | Override max. number of word pairs generated (6)                                                      |
| --no-single-pair                          | Disable single word pair generation                                                                   |
| --\[no-\]single-retest-guess              | Override config for SingleRetestGuess                                                                 |
| --wordlist\[=FILE\] --stdin               | Wordlist mode, read words from FILE or stdin                                                          |
| &nbsp;&nbsp;&nbsp;--pipe                  | like --stdin, but bulk reads, and allows rules                                                        |
|                                           |                                                                                                       |
| --rules\[=SECTION\[,..\]\]                | Enable word mangling rules (for wordlist or PRINCE modes), using default or named rules               |
| --rules=:rule\[;..\]\]                    | Same, using "immediate" rule(s)                                                                       |
| --rules-stack=SECTION\[,..\]              | Stacked rules, applied after regular rules or to modes that otherwise don't support rules             |
| --rules-stack=:rule\[;..\]                | Same, using "immediate" rule(s)                                                                       |
| --rules-skip-nop                          | Skip any NOP ":" rules (you already ran w/o rules)                                                    |
|                                           |                                                                                                       |
| --loopback\[=FILE\]                       | Like --wordlist, but extract words from a .pot file                                                   |
| --mem-file-size=SIZE                      | Size threshold for wordlist preload (default 2048 MB)                                                 |
| --dupe-suppression                        | Suppress all dupes in wordlist (and force preload)                                                    |
| --incremental\[=MODE\]                    | "Incremental" mode \[using section MODE\]                                                             |
| --incremental-charcount=N                 | Override CharCount for incremental mode                                                               |
| --external=MODE                           | External mode or word filter                                                                          |
| --mask\[=MASK\]                           | Mask mode using MASK (or default from john.conf)                                                      |
| --markov\[=OPTIONS\]                      | "Markov" mode (see doc/MARKOV)                                                                        |
| --mkv-stats=FILE                          | "Markov" stats file                                                                                   |
|                                           |                                                                                                       |
| --prince\[=FILE\]                         | PRINCE mode, read words from FILE                                                                     |
| --prince-loopback\[=FILE\]                | Fetch words from a .pot file                                                                          |
| --prince-elem-cnt-min=N                   | Minimum number of elements per chain (1)                                                              |
| --prince-elem-cnt-max=\[-\]N              | Maximum number of elements per chain (negative N is relative to word length) (8)                      |
| --prince-skip=N                           | Initial skip                                                                                          |
| --prince-limit=N                          | Limit number of candidates generated                                                                  |
| --prince-wl-dist-len                      | Calculate length distribution from wordlist                                                           |
| --prince-wl-max=N                         | Load only N words from input wordlist                                                                 |
| --prince-case-permute                     | Permute case of first letter                                                                          |
| --prince-mmap                             | Memory-map infile (not available with case permute)                                                   |
| --prince-keyspace                         | Just show total keyspace that would be produced (disregarding skip and limit)                         |
|                                           |                                                                                                       |
| --subsets\[=CHARSET\]                     | "Subsets" mode (see doc/SUBSETS)                                                                      |
| --subsets-required=N                      | The N first characters of "subsets" charset are The "required set"                                    |
| --subsets-min-diff=N                      | Minimum unique characters in subset                                                                   |
| --subsets-max-diff=\[-\]N                 | Maximum unique characters in subset (negative N is relative to word length)                           |
| --subsets-prefer-short                    | Prefer shorter candidates over smaller subsets                                                        |
| --subsets-prefer-small                    | Prefer smaller subsets over shorter candidates                                                        |
|                                           |                                                                                                       |
| --make-charset=FILE                       | Make a charset, FILE will be overwritten                                                              |
| --stdout\[=LENGTH\]                       | Just output candidate passwords \[cut at LENGTH\]                                                     |
| --session=NAME                            | Give a new session the NAME                                                                           |
| --status\[=NAME\]                         | Print status of a session \[called NAME\]                                                             |
| --restore\[=NAME\]                        | Restore an interrupted session \[called NAME\]                                                        |
| --\[no-\]crack-status                     | Emit a status line whenever a password is cracked                                                     |
| --progress-every=N                        | Emit a status line every N seconds                                                                    |
|                                           |                                                                                                       |
| --show\[=left\]                           | Show cracked passwords \[if =left, then uncracked\]                                                   |
| --show=formats                            | Show information about hashes in a file (JSON)                                                        |
| --show=invalid                            | Show lines that are not valid for selected format(s)                                                  |
| --test\[=TIME\]                           | Run tests and benchmarks for TIME seconds each (if TIME is explicitly 0, test w/o benchmark)          |
| --stress-test\[=TIME\]                    | Loop self tests forever                                                                               |
| --test-full=LEVEL                         | Run more thorough self-tests                                                                          |
|                                           |                                                                                                       |
| --no-mask                                 | Used with --test for alternate benchmark w/o mask                                                     |
| --skip-self-tests                         | Skip self tests                                                                                       |
| --users=\[-\]LOGIN\|UID\[,..\] \[Do not\] | load this (these) user(s) only                                                                        |
| --groups=\[-\]GID\[,..\]                  | Load users \[not\] of this (these) group(s) only                                                      |
| --shells=\[-\]SHELL\[,..\]                | Load users with\[out\] this (these) shell(s) only                                                     |
|                                           |                                                                                                       |
| --salts=\[-\]COUNT\[:MAX\]                | Load salts with\[out\] COUNT \[to MAX\] hashes, or                                                    |
| --salts=#M\[-N\]                          | Load M \[to N\] most populated salts                                                                  |
| --costs=\[-]\C\[:M\]\[,...\]              | Load salts with\[out\] cost value Cn\[to Mn\]. For tunable cost parameters, see doc/OPTIONS           |
| --fork=N                                  | Fork N processes                                                                                      |
| --node=MIN\[-MAX\]/TOTAL                  | This node's number range out of TOTAL count**                                                         |
|                                           |                                                                                                       |
| --save-memory=LEVEL                       | Enable memory saving, at LEVEL 1..3                                                                   |
| --log-stderr                              | Log to screen instead of file                                                                         |
| --verbosity=N                             | Change verbosity (1-5 or 6 for debug, default 3)                                                      |
| --no-log                                  | Disables creation and writing to john.log file                                                        |
| --bare-always-valid=Y                     | Treat bare hashes as valid (Y/N)                                                                      |
|                                           |                                                                                                       |
| --catch-up=NAME                           | Catch up with existing (paused) session NAME                                                          |
| --config=FILE                             | Use FILE instead of john.conf or john.ini                                                             |
| --encoding=NAME                           | Input encoding (eg. UTF-8, ISO-8859-1). See also doc/ENCODINGS.                                       |
| --input-encoding=NAME                     | Input encoding (alias for --encoding)                                                                 |
| --internal-codepage=NAME                  | Codepage used in rules/masks (see doc/ENCODINGS)                                                      |
| --target-encoding=NAME                    | Output encoding (used by format)                                                                      |
|                                           |                                                                                                       |
| --force-tty                               | Set up terminal for reading keystrokes even if we're not the foreground process                       |
| --field-separator-char=C                  | Use 'C' instead of the ':' in input and pot files                                                     |
| --\[no-\]keep-guessing                    | Try finding plaintext collisions                                                                      |
| --list=WHAT                               | List capabilities, see --list=help or doc/OPTIONS                                                     |
|                                           |                                                                                                       |
| --length=N                                | Shortcut for --min-len=N --max-len=N                                                                  |
| --min-length=N                            | Request a minimum candidate length in bytes                                                           |
| --max-length=N                            | Request a maximum candidate length in bytes                                                           |
| --max-candidates=\[-\]N                   | Gracefully exit after this many candidates tried. (if negative, reset count on each crack)            |
| --max-run-time=\[-\]N                     | Gracefully exit after this many seconds (if negative, reset timer on each crack)                      |
|                                           |                                                                                                       |
| --mkpc=N                                  | Request a lower max. keys per crypt                                                                   |
| --no-loader-dupecheck                     | Disable the dupe checking when loading hashes                                                         |
| --pot=NAME                                | Pot file to use                                                                                       |
| --regen-lost-salts=N                      | Brute force unknown salts (see doc/OPTIONS)                                                           |
| --reject-printable                        | Reject printable binaries                                                                             |
| --tune=HOW                                | Tuning options (auto/report/N)                                                                        |
| --subformat=FORMAT                        | Pick a benchmark format for --format=crypt                                                            |
| --format=\[NAME\|CLASS\]\[,..\]           | Force hash of type NAME. The supported formats can be seen with --list=formats and --list=subformats. |
\*See also doc/OPTIONS for more advanced selection of format(s), including using classes and wildcards.

## Removed from course

### Medusa

“Speedy, massively parallel, modular, login brute forcer”  
  
Usage:
```bash
Medusa [-h host|-H file] [-u username|-U file] [-p password|-P file] [-C file] -M module [OPT]
```

| Options           | Desc                                                                                                                                                                             |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **-h** \[TEXT\]   | Target hostname or IP address                                                                                                                                                    |
| **-H** \[FILE\]   | File containing target hostnames or IP addresses                                                                                                                                 |
| **-u** \[TEXT\]   | Username to test                                                                                                                                                                 |
| **-U** \[FILE\]   | File containing usernames to test                                                                                                                                                |
| **-p** \[TEXT\]   | Password to test                                                                                                                                                                 |
| **-P** \[FILE\]   | File containing passwords to test                                                                                                                                                |
| **-C** \[FILE\]   | File containing combo entries. See README for more information.                                                                                                                  |
| **-O** \[FILE\]   | File to append log information to                                                                                                                                                |
| **-e** \[n/s/ns\] | Additional password checks (\[n\] No Password, \[s\] Password = Username)                                                                                                        |
| **-M** \[TEXT\]   | Name of the module to execute (without the .mod extension)                                                                                                                       |
| **-m** \[TEXT\]   | Parameter to pass to the module. This can be passed multiple times with a different parameter each time and they will all be sent to the module (i.e. -m Param1 -m Param2, etc.) |
| **-d**            | Dump all known modules                                                                                                                                                           |
| **-n** \[NUM\]    | Use for non-default TCP port number                                                                                                                                              |
| **-s**            | Enable SSL                                                                                                                                                                       |
| **-g** \[NUM\]    | Give up after trying to connect for NUM seconds (default 3)                                                                                                                      |
| **-r** \[NUM\]    | Sleep NUM seconds between retry attempts (default 3)                                                                                                                             |
| **-R** \[NUM\]    | Attempt NUM retries before giving up. The total number of attempts will be NUM + 1.                                                                                              |
| **-c** \[NUM\]    | Time to wait in usec to verify socket is available (default 500 usec).                                                                                                           |
| **-t** \[NUM\]    | Total number of logins to be tested concurrently                                                                                                                                 |
| **-T** \[NUM\]    | Total number of hosts to be tested concurrently                                                                                                                                  |
| **-L**            | Parallelize logins using one username per thread. The default is to process the entire username before proceeding.                                                               |
| **-f**            | Stop scanning host after first valid username/password found.                                                                                                                    |
| **-F**            | Stop audit after first valid username/password found on any host.                                                                                                                |
| **-b**            | Suppress startup banner                                                                                                                                                          |
| **-q**            | Display module's usage information                                                                                                                                               |
| **-v** \[NUM\]    | Verbose level \[0 - 6 (more)\]                                                                                                                                                   |
| **-w** \[NUM\]    | Error debug level \[0 - 10 (more)\]                                                                                                                                              |
| **-V**            | Display version                                                                                                                                                                  |
| **-Z** \[TEXT\]   | Resume scan based on map of previous scan                                                                                                                                        |
|                   |                                                                                                                                                                                  |
| Modules           | Available modules in "_/usr/lib/x86_64-linux-gnu/medusa/modules_"                                                                                                                |
| cvs.mod           | Brute force module for CVS sessions : version 2.0                                                                                                                                |
| ftp.mod           | Brute force module for FTP/FTPS sessions : version 2.1                                                                                                                           |
| http.mod          | Brute force module for HTTP : version 2.1                                                                                                                                        |
| imap.mod          | Brute force module for IMAP sessions : version 2.0                                                                                                                               |
| mssql.mod         | Brute force module for M$-SQL sessions : version 2.0                                                                                                                             |
| mysql.mod         | Brute force module for MySQL sessions : version 2.0                                                                                                                              |
| nntp.mod          | Brute force module for NNTP sessions : version 2.0                                                                                                                               |
| pcanywhere.mod    | Brute force module for PcAnywhere sessions : version 2.0                                                                                                                         |
| pop3.mod          | Brute force module for POP3 sessions : version 2.0                                                                                                                               |
| postgres.mod      | Brute force module for PostgreSQL sessions : version 2.0                                                                                                                         |
| rexec.mod         | Brute force module for REXEC sessions : version 2.0                                                                                                                              |
| rlogin.mod        | Brute force module for RLOGIN sessions : version 2.0                                                                                                                             |
| rsh.mod           | Brute force module for RSH sessions : version 2.0                                                                                                                                |
| smbnt.mod         | Brute force module for SMB (LM/NTLM/LMv2/NTLMv2) sessions : version 2.1                                                                                                          |
| smtp-vrfy.mod     | Brute force module for verifying SMTP accounts (VRFY/EXPN/RCPT TO) : version 2.1                                                                                                 |
| smtp.mod          | Brute force module for SMTP Authentication with TLS : version 2.0                                                                                                                |
| snmp.mod          | Brute force module for SNMP Community Strings : version 2.1                                                                                                                      |
| ssh.mod           | Brute force module for SSH v2 sessions : version 2.1                                                                                                                             |
| svn.mod           | Brute force module for Subversion sessions : version 2.1                                                                                                                         |
| telnet.mod        | Brute force module for telnet sessions : version 2.0                                                                                                                             |
| vmauthd.mod       | Brute force module for the VMware Authentication Daemon : version 2.0                                                                                                            |
| vnc.mod           | Brute force module for VNC sessions : version 2.1                                                                                                                                |
| web-form.mod      | Brute force module for web forms : version 2.1                                                                                                                                   |
| wrapper.mod       | Generic Wrapper Module : version 2.0                                                                                                                                             |

### Crowbar

Network authentication cracking tool (primarily designed to leverage SSH keys rather than pws)  
  
*As RDP doesn't reliably handle multiple threads, make sure to **-n 1** if you're attacking it.  
  
| Options                                                                 | Desc                                                               |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **-h**, --help                                                          | Show this help message and exit                                    |
| **-b** {openvpn,rdp,sshkey,vnckey}, --brute {openvpn,rdp,sshkey,vnckey} | Target service                                                     |
| **-s** SERVER, --server SERVER                                          | Static target                                                      |
| **-S** SERVER_FILE, --serverfile SERVER_FILE                            | Multiple targets stored in a file                                  |
| **-u** USERNAME \[USERNAME ...\], --username USERNAME \[USERNAME ...\]  | Static name to login with                                          |
| **-U** USERNAME_FILE, --usernamefile USERNAME_FILE                      | Multiple names to login with, stored in a file                     |
| **-n** THREAD, --number THREAD                                          | Number of threads to be active at once                             |
| **-l** FILE, --log FILE                                                 | Log file (only write attempts)                                     |
| **-o** FILE, --output FILE                                              | Output file (write everything else)                                |
| **-c** PASSWD, --passwd                                                 | PASSWD Static password to login with                               |
| **-C** FILE, --passwdfile FILE                                          | Multiple passwords to login with, stored in a file                 |
| **-t** TIMEOUT, --timeout TIMEOUT                                       | \[SSH\] How long to wait for each thread (seconds)                 |
| **-p** PORT, --port PORT                                                | Alter the port if the service is not using the default value       |
| **-k** KEY_FILE, --keyfile KEY_FILE                                     | \[SSH/VNC\] (Private) Key file or folder containing multiple files |
| **-m** CONFIG, --config CONFIG                                          | \[OpenVPN\] Configuration file                                     |
| **-d**, --discover                                                      | Port scan before attacking open ports                              |
| **-v**, --verbose                                                       | Enable verbose output (-vv for more)                               |
| **-D**, --debug                                                         | Enable debug mode                                                  |
| **-q**, --quiet                                                         | Only display successful logins                                     |


