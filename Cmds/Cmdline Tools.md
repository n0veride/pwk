
# apt
#linuxCmd #pkgInstaller

Advanced Package Tool  
  
Complete package management system that recursively installs, removes, or updates the requested package by recursively satisfying its requirements and dependencies.  
A package is an archive file containing multiple _.deb_ files. **dpkg** will install directly from the _.deb_ file, but miss dependencies whereas **apt** will not.  
  
When updating or installing a program, the system queries the software repositories (_/etc/apt/sources.list_) for the desired package.  

| Options  |                             |
| :--------: | --------------------------- |
| **apt-cache search**              | Displays all/ given package information stored in the internal cache database/ repository - Keywords given will match via description not its name.|
| **autoremove**                    | Removes packages that were automatically installed to satisfy dependencies for other packages and are now no longer needed                          |
| **-f / --fix-broken** **install** | Fixes missing package dependencies and repairs existing installs                                                                                    |
| **--fix-missing** **update**      | Ignores missing package dependencies                                                                                                                |
| **list**                          | Lists packages                                                                                                                                      |
| **--installed**                   | List all installed packages                                                                                                                         |
| **purge**                         | Uninstalls package data and its config files                                                                                                        |
| **remove**                        | Uninstalls package data, but will leave behind user config files and dependencies                                                                   |
| **--purge**                       | Also removes config files                                                                                                                           |
| **show** _package_                | Displays information about the package's dependencies, installation size, the package source, etc.                                                  |
| -**update**                       | Update the cached list of available packages, including information related to their versions, descriptions, etc.                                   |
| -**upgrade**                      | Upgrade installed packages (or given packages) and core systems to the latest versions                                                              |

If there's an "...invalic... not yet valid for x time" error, try:
```bash
sudo apt -o Acquire::Check-Valid-Until=false -o Acquire::Check-Date=false update
```


# arp
#linuxCmd #networkEnum

Prints content of ARP table

| Options |                                                                 |
|:-------:| --------------------------------------------------------------- |
| **-a**  | Uses BSD style output formatting (no fixed columns)             |
| **-e**  | Uses default Linux style output formatting (with fixed columns) |
| **-n**  | Uses numerical addresses rather than symbolic names             |
| **-v**  | Verbose                                                         |


# awk
#linuxCmd #textProcessing

A programming language designed for text processing and is typically used as a data extraction and reporting tool.  
Can have multiple character delimiter.  
  
| Options  |                      |
|:--------:| -------------------- |
| **$**_n_ | Denotes field number |
|  **-F**  | Field separator      |

```bash
echo "hello::there::friend" | awk -F "::" '{print $1, $3}'  
	hello friend
```

Sort file text by length:
```bash
awk '{print length(), $0 | "sort -n"}' values_and_flags.txt
```


# axel
#linuxCmd #dataTransfer

Download accelerator that transfers a file from a FTP or HTTP server through multiple connections.  

|  Options   |                                                   |
|:----------:| ------------------------------------------------- |
|   **-a**   | More consise progress indicator                   |
| **-n** _x_ | Specifies x number of connections to use          |
|   **-o**   | Allows saving file to given directory/ file name. |


# comm
#linuxCmd #fileProcessing 

Compares two text files, displaying the lines that are unique to each one, as well as the lines they have in common. It outputs three space-offset columns:  
the first contains lines that are unique to the first file or argument;  
the second contains lines that are unique to the second file or argument;  
the third column contains lines that are shared by both files.  
  
| Options  |                             |
|:--------:| --------------------------- |
| **-**_n_ | Suppress line _n_ in output |


# compgen
#linuxCmd #userRecon

Used to list all the commands that could be executed within the Linux system.

| Options |                                                       |
|:-------:| ----------------------------------------------------- |
| **-a**  | Display all bash shell aliases available to your user |
| **-b**  | Display all bash built-ins                            |
| **-c**  | Display all commands available to your user           |
| **-k**  | Display all bash keywords                             |


# curl
#linuxCmd #winCmd #dataTransfer

Transfer data to or from a server using a host of protocols including IMAP/S, POP3/S, SCP, SFTP, SMB/S, SMTP/S, TELNET, TFTP, etc

|         Options         |                                                                      |
|:-----------------------:| -------------------------------------------------------------------- |
|         **-A**          | Set User-Agent                                                       |
| **-b** _name=value_ | Sets cookie to _name=value_ pair                                     |
|         **-d**          | Sends specified data in a POST request                               |
|         **-H**          | Set request headers*                                                 |
|         **-I**          | Grab headers only (sends HEAD request)                               |
|         **-i**          | Display headers and the response body (sends any request we specify) |
|         **-k**          | Skip TLS/ SSL cert check                                             |
|         **-o**          | Allows saving file to given directory/ file name                     |
|         **-X**          | Specify custom request method                                        |
|         **-v**          | Verbose. Allows viewing of full HTTP request and response            |
|  **-u** _username:pw_   | Login                                                                |

  
\*Setting the Content-Type so the webserver knows we're sending form data:
```bash
-H “Content-Type: application/x-www-form-urlencoded”
```


# cut
#linuxCmd #textProcessing 

Extract a section of text from a line and output it to STDOUT  
Can only use a single character delimiter  

|  Options  |             |
|:-------:| ----------- |
|**-d**|Denotes field delimiter|
|**-f**|Denotes field number

```bash
echo "I hack binaries,web apps,mobile apps, and just about anything else"| cut -f 2 -d ","  
web apps  
  
cut -d ":" -f 1 /etc/passwd   
root   
daemon   
bin   
....
```


# diff
#linuxCmd #fileProcessing 

Detect differences between files, similar to [**comm**](#comm), but more complex and supports many output formats.  
**-** indicator signals the line unique to the first file  
**+** indicator signals the line unique to the second file  

| Options |                                                               |
|:-------:| ------------------------------------------------------------- |
| **-c**  | Context format                                                |
| **-u**  | Unified format - does not show lines that match between files |


# dig
#linuxCmd #winCmd #siteEnum

DNS Lookup utility

Usage:
```bash
dig <type> <domain> <addt options>
```

|       Options       |                                                                                         |
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


Zone transfers:
```bash
dig [domain] ANY +nostat +nocmd +nocomments
			OR
dig [domain] @[nameserver]
```


# dpkg
#linuxCmd #pkgInstaller

Core tool used to install a package, either directly or indirectly through **apt**. Used to install _.deb_ files  
Can be used offline. Will NOT install dependencies.  

| Options | |
| :-----: | ---- |
|**-i**|Install|
|**-r**|Remove|
|**-P**|Purge|


# env
#linuxCmd #terminalEnv #envRecon

Display [environment variables](Env%20Vars.md) within current Bash shell


# export
#linuxCmd #terminalEnv

Define variables within Bash terminal that are accessable to any subprocesses spawned from current Bash instance. Use **$** to reference the variable.  
  
Adding an [environment variable](Env%20Vars.md) without export it will only be available in the current shell.

```bash
export victim_ip=10.11.1.220  
ping -c 4 $victim_ip
```


# find
#linuxCmd #envRecon #fileProcessing 

Searches for given files and directories    
  
| Addts | | |
|:--------------:| --- | --- |
|**2>/dev/null**|Sinkholes stderr messages to null||
|**-exec**|||
||**{}**|Ran w/ **exec**. Expands command to the filename of each of the files/ directories found by **find**|
||**\;**|Ends command ran by **exec**. Must be escaped (hence **\\**). Runs command per file|
||**+**|Ends command ran by **exec**. Appends found files to end of the command so command is run only once. More efficient than **\;**|
  
```bash
find / -size 64c -exec grep -Hi base64 {} \;
```


|         Options          |                                                                                                                  |
|:------------------------:| ---------------------------------------------------------------------------------------------------------------- |
|      **-mmin** _n_       | Searches for files modified >,<,= _n_ minutes ago ( +_n_ for greater than, -_n_ for less than, _n_ for exactly)  |
|      **-mtime** _n_      | Searches for files modified >,<,= _n_ * 24 hrs ago ( +_n_ for greater than, -_n_ for less than, _n_ for exactly) |
|     **-perm** _mode_     | File's [permission bits](Perms.md) are exactly set to _mode_                                                     |
|       **-**_mode_        | **All** file's permission bits are set to _mode_                                                                     |
|       **/**_mode_        | **Any** file's permission bits are set to _mode_                                                                     |
|        **-empty**        | Finds all empty files and directories                                                                            |
| **-type** **d**_/_ **f** | Only match directories/ files.                                                                                   |
|       **-delete**        | Delete files. Always put this option at the end of the find command                                              |

  
Looks for files/ dirs with the SUID bit set:
```bash
find / -perm -u=s.....
```


# grep
#linuxCmd #textProcessing #fileProcessing

Searches text files for the occurence of a given regex and displays results to STDOUT  

|  Options   |                                                                                                                             |
|:----------:| --------------------------------------------------------------------------------------------------------------------------- |
| **-A** _n_ | Display result and _n_ lines after                                                                                          |
| **-B** _n_ | Display result and _n_ lines before                                                                                         |
|   **-H**   | Show file name                                                                                                              |
|   **-i**   | Ignore text case                                                                                                            |
|   **-o**   | Useful w/ regex. Print only the matched (non-empty) parts of a matching line, with each such part on a separate output line |
|   **-r**   | Recursive searching                                                                                                         |
|   **-s**   | Suppress errors                                                                                                             |
|   **-v**   | Return all non-matching lines                                                                                               |
|   **-x**   | Equivalent to wrapping with regex of **^** and **$**                                                                        |
|   **^**    | Beginning of line                                                                                                           |
|   **$**    | End of line                                                                                                                 |

Similar to Win [**findstr**](Cmdline%20Tools.md#findstr)


# history
#linuxCmd #terminalEnv #envRecon 

Display history of Bash commands. Operation of **history** can be changed by different [environment variables](Env%20Vars.md)


# host
#linuxCmd #winCmd #siteEnum

Queries DNS for domain name to IP address translation  

| Options |                                                               |
|:-------:| ------------------------------------------------------------- |
| **-a**  | Showes all DNS records available. Equivilant to **-v -t ANY** |
| **-l**  | Lists zone. Must add \<domain name\> \<dns server address\>   |
| **-p**  | Specifies port on the server to query (default is 53)         |
| **-t**  | Specifies DNS record to query (Default is A Record)           |
| **-v**  | Verbose                                                       |

List zone: The host command performs a zone transfer of zone name and prints out the NS, PTR and address records (A/AAAA).  
Together, the **-l -a** options print all records in the zone.  

Find all namespaces:  
```bash
host -t ns [domain] | cut -d " " -f 4
```
  
Zone transfers:  
```bash
host -l [domain] [nameserver]
```


# ip
#linuxCmd #networkEnum 

Utility to show or manipulate routing, network devices, interfaces and tunnels.

Ethernet connections only.  For wireless use [*iwconfig*](Cmdline%20Tools.md#iwconfig)

| Options |                                                                          |
|:-------:| ------------------------------------------------------------------------ |
|  **a**  | Show all                                                                 |
|  **n**  | Display ARP table (can also use [*arp*](Cmdline%20Tools.md#arp) command) |
|  **r**  | Displays Route table (can also use [*route*](route.md) command)          |

|      Cmd       | Replacement For |
|:--------------:|:---------------:|
|  **ip route**  | **netstat -r**  |
| **ip -s link** | **netstat -i**  |
|  **ip maddr**  | **netstat -g**  |


# iwconfig
#linuxCmd #networkEnum 

Shows wireless networking connections.   For ethernet, use [*ip*](Cmdline%20Tools.md#ip) or *ipconfig*


# kill
#linuxCmd #processes

Sends signal to process for given PID  
  
Default signal sent is SIGTERM (request termination)  

|          Options           |                                                                                           |                                   |
|:--------------------------:| ----------------------------------------------------------------------------------------- | --------------------------------- |
| **-** _signal_ OR **-s** _ | Send specified _signal_ by signal number or name                                          | ex: **-9** - Force kill (SIGKILL) |
|           **-l**           | List signal names. When given optional argument, will convert signal name ↔ signal number |                                   |
|           **-L**           | List signals in a tabular format                                                          |                                   |

  
Available Signals:  
1) SIGHUP 2) SIGINT 3) SIGQUIT 4) SIGILL 5) SIGTRAP  
6) SIGABRT 7) SIGBUS 8) SIGFPE 9) SIGKILL 10) SIGUSR1  
11) SIGSEGV 12) SIGUSR2 13) SIGPIPE 14) SIGALRM 15) SIGTERM  
16) SIGSTKFLT 17) SIGCHLD 18) SIGCONT 19) SIGSTOP 20) SIGTSTP  
21) SIGTTIN 22) SIGTTOU 23) SIGURG 24) SIGXCPU 25) SIGXFSZ  
26) SIGVTALRM 27) SIGPROF 28) SIGWINCH 29) SIGIO 30) SIGPWR  
 ?) SIGSYS 34) SIGRTMIN 35) SIGRTMIN+1 36) SIGRTMIN+2 37) SIGRTMIN+3  
 ?) SIGRTMIN+4 39) SIGRTMIN+5 40) SIGRTMIN+6 41) SIGRTMIN+7 42) SIGRTMIN+8  
 ?) SIGRTMIN+9 44) SIGRTMIN+10 45) SIGRTMIN+11 46) SIGRTMIN+12 47) SIGRTMIN+13  
 ?) SIGRTMIN+14 49) SIGRTMIN+15 50) SIGRTMAX-14 51) SIGRTMAX-13 52) SIGRTMAX-12  
 ?) SIGRTMAX-11 54) SIGRTMAX-10 55) SIGRTMAX-9 56) SIGRTMAX-8 57) SIGRTMAX-7  
 ?) SIGRTMAX-6 59) SIGRTMAX-5 60) SIGRTMAX-4 61) SIGRTMAX-3 62) SIGRTMAX-2  
63) SIGRTMAX-1 64) SIGRTMAX

# locate
#linuxCmd #envRecon #fileProcessing 

Searches filesystem for files and directories for a given pattern. Consults locate.db which is updated regularly by **cron** and manually with **updatedb**


# ls
#linuxCmd #fileProcessing #envRecon 

Prints basic file listing  
  
| Options |                                                                        |
|:-------:| ---------------------------------------------------------------------- |
| **-1**  | Displays each file on a single line                                    |
| **-a**  | Show all files                                                         |
| **-h**  | Human readable (w/ **-l** and **-s**, show sizes like 1K, 3M, 2G, etc) |
| **-i**  | Show inode number                                                      |
| **-l**  | Long listing format                                                    |
| **-t**  | Sort by last modified date and time                                    |
| **-r**  | Reverse sorting by modified date and time                              |



# lsblk
#linuxCmd #deviceEnum



# ltrace
#linuxCmd #processes 

Runs the specified command until it exits. 

It **intercepts and records the dynamic library calls which are called by the executed process and the signals which are received by that process**.
It can also intercept and print the system calls executed by the program.

```bash
ltrace dpkg
```


# man
#linuxCmd #processes 

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

Show information for the **passwd** command (section 1 of the manual).
```bash
man passwd
```

Show information for the /etc/passwd file (section 5 of the manual).
```bash
man 5 passwd
```

**-k** - Search manpage descriptions for given keyword and display results. Equivalent to **apropos**.   Using regex:
```bash
man -k '^passwd$'
```
	enclosed by **^** and **$** will ensure matching of entire line and no sub-string matches


|  Navigation   |                                       |
|:-------------:| ------------------------------------- |
|     **/**     | Search for specified text w/in manual |
|     **N**     | Next search result                    |
| **Shift + N** | Previous search result                |


# mkdir
#linuxCmd

Creates specified directory  

| Options |                                                                  |
|:-------:| ---------------------------------------------------------------- |
| **-p**  | Make multiple directories and their parent directories as needed |
| **{}**  | Create multiple directories w/ lists                             |

```bash
mkdir -p test/recon

mkdir -p test/{recon,exploit,report}  
mkdir {a-z}
```


# mount
#linuxCmd  #deviceManipulation

Mount a filesystem.  
  
Usage:  
```bash
mount <device> <dir>
```

_/etc/fstab_ may contain lines describing what devices are usually mounted, where, and using which options.  
  
To override mount options from _/etc/fstab_, you need to use the **-o** switch ---- Multiple options can be strung together with a _**,**_  

|   Options    |                                             |     |
|:------------:| ------------------------------------------- | ----- |
|    **-o**    | Override mount options from /etc/fstab      |     |
|    |  **nolock**  | Disable file locking (used w/ **-o**)       |
|    | **vers=**_n_ | Mounts via NFS version _n_ (used w/ **-o**) |


Remove a persistant share:  
```bash
unmount -f -l /mnt/dir
```


# netstat
#linuxCmd #winCmd #networkEnum 

Network Statistics   

Mostly obsolete. Useful in Windows  
  
Replacement for netstat is **ss**  
Replacement for **netstat -r** is **ip route**.  
Replacement for **netstat -i** is **ip -s link**.  
Replacement for **netstat -g** is **ip maddr**  
  

**<#>** - Automatically refresh every <#> seconds
**-a** - Display all active (listening & non-listening) TCP connections
**-b** - Display .exe (or .dll) name associated w/ listening process (req admin/ root)
**-c** - Continuous monitoring: Print info from route cache.
**-g** - Display multicast group membership info
**-i** - Display table of all network interfaces
**-l** - Display only listening sockets
**-m** - Display list of masqueraded conns
**-n** - Display address & port number in numerical form (Turns off name resolution)
**-o** - Display owner PID of each conn  
**-p** - Display process PID & name the conn belongs to
**-r** - Display kernel routing tables
**-s** - Display statistics for each protocol
**-t** - Display TCP only
**-u** - Display UDP only
**-w** - Display raw information