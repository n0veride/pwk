
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



# Active Info Gathering
### DNS

