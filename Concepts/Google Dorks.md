
Using creative refinement of search queries to uncover critical information, vulnerabilities, and misconfigured websites.  
Can find more w/ the [Google Hacking Database GHDB](https://www.exploit-db.com/google-hacking-database)  
  
**-**: Used to exclude. Great for viewing non-HTML pages  
  
**site**: Limits searches to a single domain. Can be used to get an idea of an org's web presence.  

**filetype** or **ext**: Limits searches to a specified file type. Ex:
```bash
site:megacorpone.com filetype:php
```
The ext operator could also be helpful to discern what programming languages might be used on a web site.  
Searches like **ext:jsp**, **ext:cfm**, **ext:pl** will find indexed Java Server Pages, Coldfusion, and Perl pages respectively.  
  

**intitle**: Finds pages with given words or strings in them.  
Ex: intitle:“index of” “parent directory” - Shows results w/ “index of” in the title and “parent directory” somewhere on the page.  
File contents of directories without index pages.  
Able to find interesting files and sensitive info through these misconfigurations.  


great way to search for subdomains of a site while ignoring www.  
```bash
site:*.megacorpone.com -site:www.megacorpone.com
```