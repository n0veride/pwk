
Displays manual of specified command.  
  
The Unix manual consists of eight sections, and each man page has its command name followed by the section number in parenthesis.

| Section# | Topic                                               |
| -------- | --------------------------------------------------- |
| 1        | Commands available to users                         |
| 2        | Unix and C system calls                             |
| 3        | C library routines for C programs                   |
| 4        | Special file names                                  |
| 5        | File formats and conventions for files used by Unix |
| 6        | Games                                               |
| 7        | Word processing packages                            |
| 8        | System administration commands and procedures       |

Ex:
```bash
man passwd
```
	will show information for the **passwd** command (section 1 of the manual).

Ex:
```bash
man 5 passwd
```
	will show information for the /etc/passwd file (section 5 of the manual).


**-k** - Search manpage descriptions for given keyword and display results. Equivilent to **apropos**.   Using regex:
```bash
man -k '^passwd$'
```
	enclosed by **^** and **$** will ensure matching of entire line and no sub-string matches


**/** - Search for specified text w/in manual  
**N** - Next search result  
**Shift + N** - Previous search result