
[https://github.com/pentestmonkey/windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)  
  
  
Usage:
```powershell
windows_privesc_check.exe (--dump [ dump opts] | --dumptab | --audit) [examine opts] [host opts] -o report-file-stem
```
  
Options:  
**--version** -      Show program's version number and exit  
-h, --help -      Show this help message and exit  
--dump -      Dumps info for you to analyse manually  
--dumptab -      Dumps info in tab-delimited format  
--audit -      Identify and report security weaknesses  
--pyshell -      Start interactive python shell  
  
###### examine opts:  
At least one of these to indicate what to examine (*=not implemented)  
  
-a, --all -      All Simple Checks (non-slow)  
-A, --allfiles -      All Files and Directories (slow)  
-D, --drives -      Drives  
-e, --reg_keys -      Misc security-related reg keys  
-E, --eventlogs -      Event Log*  
-f INTERESTING_FILE_LIST, --interestingfiledir=INTERESTING_FILE_LIST -      Changes -A behaviour. Look here INSTEAD  
-F INTERESTING_FILE_FILE, --interestingfilefile=INTERESTING_FILE_FILE -      Changes -A behaviour. Look here INSTEAD. On dir per line  
-G, --groups -      Groups  
-H, --shares -      Shares  
-I, --installed_software -      Installed Software  
-j, --tasks -      Scheduled Tasks  
-k, --drivers -      Kernel Drivers  
-L, --loggedin      Logged In  
-O, --ntobjects      NT Objects  
-n, --nointerestingfiles  
				Changes -A/-f/-F behaviour. Don't report interesting  files  
-N, --nounreadableif - Changes -A/-f/-F behaviour.      Report only interesting files readable by untrsuted users (see -x, -X, -b, -B)  
-P, --progfiles      Program Files Directory Tree  
-r, --registry      Registry Settings + Permissions  
-R, --processes      Processes  
-S, --services vWindows Services  
-t, --paths      PATH  
-T PATCHFILE, --patches=PATCHFILE -      Patches. Arg is filename of xlsx patch info. Download from [http://go.microsoft.com/fwlink/?LinkID=245778](http://go.microsoft.com/fwlink/?LinkID=245778) or pass 'auto' to fetch automatically  
-U, --users      Users  
-v, --verbose      More verbose output on console  
-W, --errors      Die on errors instead of continuing (for debugging)  
-z, --noappendices      No report appendices in --audit mode  
  
###### host opts:  
Optional details about a remote host (experimental). Default is  
current host.  
  
-s REMOTE_HOST, --server=REMOTE_HOST -      Remote host or IP  
-u REMOTE_USER, --user=REMOTE_USER -      Remote username  
-p REMOTE_PASS, --pass=REMOTE_PASS -      Remote password  
-d REMOTE_DOMAIN, --domain=REMOTE_DOMAIN -      Remote domain  
  
###### dump opts:  
Options to modify the behaviour of dump/dumptab mode  
  
-M, --get_modals -     Dump password policy, etc.  
-V, --get_privs -     Dump privileges for users/groups  
  
###### report opts:  
Reporting options  
  
-o REPORT_FILE_STEM, --report_file_stem=REPORT_FILE_STEM -      Filename stem for txt, html report files  
-x IGNORE_PRINCIPAL_LIST, --ignoreprincipal=IGNORE_PRINCIPAL_LIST -      Don't report privesc issues for these users/groups  
-X IGNORE_PRINCIPAL_FILE, --ignoreprincipalfile=IGNORE_PRINCIPAL_FILE -      Don't report privesc issues for these users/groups  
-0, --ignorenoone -     No one is trusted (even Admin, SYSTEM). hyphen zero  
-c, --exploitablebycurrentuser -      Report only privesc issues relating to current user  
-b EXPLOITABLE_BY_LIST, --exploitableby=EXPLOITABLE_BY_LIST -      Report privesc issues only for these users/groups  
-B EXPLOITABLE_BY_FILE, --exploitablebyfile=EXPLOITABLE_BY_FILE -      Report privesc issues only for these user/groupss