

Command line search tool for Exploit-DB that allows us to take an offline copy of the Exploit Database with us wherever  
  
  
Example Usage:  
```bash
searchsploit remote smb microsoft windows
```

**-c** - Perform a case-sensitive search (Default is inSEnsITiVe).  
**-e** - Perform an EXACT match on exploit title (Default is AND) \[Implies **-t**\]  
**-h** - Show this help screen.  
**-j** - Show result in JSON format.  
**-m** - Mirror (aka copies) an exploit to the current working directory  
**-o** - Exploit titles are allowed to overflow their columns.  
**-p** - Show the full path to an exploit (and also copies the path)  
**-t** - Search JUST the exploit title  
**-u** - Check for and install any exploitdb package updates  
**-w** - Show URLs to Exploit-DB.com rather than the local path.  
**-x** - Examine (aka opens) the exploit using $PAGER.  
**--colour** - Disable colour highlighting in search results.  
**--id** - Display the EDB-ID value rather than local path.  
**--nmap** - Checks all results in Nmap's XML output with service version  
Use "-v" (verbose) to try even more combinations  
**--exclude=** - Remove values from results. Use “|” to chain terms  
e.g. --exclude="term1|term2|term3".