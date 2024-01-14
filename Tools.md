
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


### recon-ng

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

### [pastebin](https://pastebin.com)

Used for storing and sharing text. Search was removed, so have to use google dorks for results

### theHarvester

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


### [social-searcher](https://www.social-searcher.com)

Social media search engine.
Search across social media for keywords and users

###  [haveibeenpwned.com/PwnedWebsites](https://haveibeenpwned.com/PwnedWebsites) 

Contains info on breached websites.

### twofi
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


### linkedin2username

Script for generating username lists based on LinkedIn data.  
Requires valid LinkedIn creds and depends on a connection to individuals in the target org.  
  
[github.com/inistring/linkedin2username](http://github.com/inistring/linkedin2username)

### [OSINT Framework](https://osintframework.com)

Includes info gathering tools and websites in one central location 

### [maltego](https://www.maltego.com/maltego-community/)

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

### .
