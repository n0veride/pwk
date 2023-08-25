
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
#linuxCmd #winCmd #dnsRecon #siteEnum

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
|  **r**  | Displays Route table (can also use [*route*](Cmdline%20Tools.md#route) command)          |

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

List block devices.  

|               Options               |                                                                                                                               |
|:-----------------------------------:| ----------------------------------------------------------------------------------------------------------------------------- |
|        **-A**, **--noempty**        | Don’t print empty devices                                                                                                     |
|            **-a**, --all            | Disable all built-in filters and list all empty devices and  RAM disk devices too                                             |
|           **-b**, --bytes           | Print the sizes in bytes rather than in a human-readable format*                                                              |
|        **-D**, **--discard**        | Print information about the discarding capabilities (TRIM, UNMAP) for each device                                             |
|        **-d**, **--nodeps**         | Do not print holder devices or slaves. For example, lsblk                                                                     |
|        **--nodeps /dev/sda**        | Prints information about the sda device only                                                                                  |
|       **-E**, --dedup column        | Use _column_ as a de-duplication key to de-duplicate output tree\*\*                                                          |
|    **-e**, **--exclude** _list_     | Exclude the devices specified by the comma-separated list of major device numbers\*\*\*                                       |
|            **-f**, --fs             | Output info about filesystems\*\*\*\*                                                                                         |
|       **-I**, --include list        | Include devices specified by the comma-separated list of major device numbers\*\*\*\*\*                                       |
|         **-i**, **--ascii**         | Use ASCII characters for tree formatting                                                                                      |
|         **-J**, **--json**          | Use JSON output format. It’s strongly recommended to use **--output** and also **--tree** if necessary                        |
|         **-l**, **--list**          | Produce output in the form of a list\*\*\*\*\*\*                                                                              |
|           **-M**, --merge           | Group parents of sub-trees to provide more readable output for RAIDs and Multi-path devices. The tree-like output is required |
|         **-m**, **--perms**         | Output info about device owner, group and mode. This option is equivalent to **-o NAME,SIZE,OWNER,GROUP,MODE**.               |
|           **-N**, --nvme            | Output info about NVMe devices only                                                                                           |
|          **-v**, --virtio           | Output info about virtio devices only                                                                                         |
|        **-n**, --noheadings         | Do not print a header line                                                                                                    |
|        **-o**, --output list        | Specify which output columns to print                                                                                         |
|      **-O**, **--output-all**       | Output all available columns\+                                                                                                |
|           **-P**, --pairs           | Produce output in the form of key="value" pairs\+\+                                                                           |
|           **-p**, --paths           | Print full device paths                                                                                                       |
|            **-r**, --raw            | Produce output in raw format.\+\+\+                                                                                           |
|           **-S**, --scsi            | Output info about SCSI devices only. All partitions, slaves and holder devices are ignored                                    |
|          **-s**, --inverse          | Print dependencies in inverse order. If the --list output is requested then the lines are still ordered by dependencies       |
| **-T**, **--tree**\[**=**_column_\] | Force tree-like output format. If column is specified, then a tree is printed in the column. The default is NAME column       |
|         **-t**, --topology          | Output info about block-device topology                                                                                       |
|         **-h**, **--help**          | Display help text and exit                                                                                                    |
|          **-V**, --version          | Print version and exit                                                                                                        |
|       **-w**, --width number        | Specifies output width as a number of characters\+\+\+\+                                                                      |
|     **-x**, **--sort** _column_     | Sort output lines by column.  Default --list; can try --tree                                                                  |
|         **-y**, **--shell**         | The column name will be modified to contain only characters allowed for shell variable identifiers                            |
|           **-z**, --zoned           | Print the zone related information for each device                                                                            |
|       **--sysroot** directory       | Gather data for a Linux instance other than the instance from which the **lsblk** command is issued                           |


\* - By default, the unit, sizes are expressed in, is byte, and unit prefixes are in power of 2^10 (1024).
Abbreviations of symbols are exhibited truncated in order to reach a better readability, by exhibiting alone the first letter of them;  
	examples: "1 KiB" and "1 MiB" are respectively exhibited as "1 K" and "1 M", then omitting on purpose the mention "iB", which is part of these abbreviations.

\*\* - If the key is not available for the device, or the device is a partition and parental whole-disk device provides the same key than the device is always printed.
The usual use case is to de-duplicate output on system multi-path devices, for example by **-E WWN**.

\*\*\* - Note that RAM disks (major=1) are excluded by default if **--all** is not specified.
The filter is applied to the top-level devices only.
This may be confusing for **--list** output format where hierarchy of the devices is not obvious.

\*\*\*\* - This option is equivalent to **-o NAME,FSTYPE,FSVER,LABEL,UUID,FSAVAIL,FSUSE%,MOUNTPOINTS**.  
The authoritative information about filesystems and raids is provided by the [blkid(8)](https://man7.org/linux/man-pages/man8/blkid.8.html) command

\*\*\*\*\* - The filter is applied to the top-level devices only.
This may be confusing for **--list** output format where hierarchy of the devices is not obvious.

\*\*\*\*\*\* - The output does not provide information about relationships between devices and
since version 2.34 every device is printed only once if **--pairs** or **--raw** not specified (the parsable outputs are  
maintained in backwardly compatible way).

\+ - Use --help to get a list of all supported columns. The columns may affect  
tree-like output. The default is to use tree for the column 'NAME' (see also **--tree**).  
The default list of columns may be extended if _list_ is specified in the format _+list_ (e.g., **lsblk -o +UUID**).  
  
\+\+ - The output lines are still ordered by dependencies. All potentially unsafe value characters are hex-escaped (\x\<code\>).
See also option **--shell**.

\+\+\+ - The output lines are still ordered by dependencies.
All potentially unsafe characters are hex-escaped (\x\<code\>) in the NAME, KNAME, LABEL, PARTLABEL and MOUNTPOINT columns.

\+\+\+\+ - The default is the number of the terminal columns, and if not executed on a terminal, then output width is not restricted at all by default.
This option also forces lsblk to assume that terminal control characters and unsafe characters are not  allowed.
The expected use-case is for example when lsblk is used by the watch(1) command. 


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

|      Cmd       |  Replaced by   |
|:--------------:|:--------------:|
|  **netstat**   |     **ss**     |
| **netstat -r** |  **ip route**  |
| **netstat -i** | **ip -s link** |
| **netstat -g** |  **ip maddr**  |
  
| Options |                                                                               |
|:-------:| ----------------------------------------------------------------------------- |
| **_n_** | Automatically refresh every _n_ seconds                                       |
| **-a**  | Display all active (listening & non-listening) TCP connections                |
| **-b**  | Display .exe (or .dll) name associated w/ listening process (req admin/ root) |
| **-c**  | Continuous monitoring: Print info from route cache                            |
| **-g**  | Display multicast group membership info                                       |
| **-i**  | Display table of all network interfaces                                       |
| **-l**  | Display only listening sockets                                                |
| **-m**  | Display list of masqueraded conns                                             |
| **-n**  | Display address & port number in numerical form (Turns off name resolution)   |
| **-o**  | Display owner PID of each conn                                                |
| **-p**  | Display process PID & name the conn belongs to                                |
| **-r**  | Display kernel routing tables                                                 |
| **-s**  | Display statistics for each protocol                                          |
| **-t**  | Display TCP only                                                              |
| **-u**  | Display UDP only                                                              |
| **-w**  | Display raw information                                                       |


# nslookup
#linuxCmd #winCmd #dnsRecon

Query DNS servers
  
Usage:
```bash
nslookup [-option] [name | -] [server]
```

When no nameserver is given, the default is used


# ps
#linuxCmd #processes #envRecon 

Lists processes system-wide. Also predefined alias for **Get-Process** cmdlet in powershell  
  
|       Options        |                                                                                                                         |
|:--------------------:| ----------------------------------------------------------------------------------------------------------------------- |
|        **-a**        | Select all processes of all users                                                                                       |
|        **-u**        | Select by effective user ID (EUID) or name. User-oriented format that provides detailed information about the processes |
|        **-x**        | List the processes without a controlling terminal                                                                       |
|        **-C**        | Select by command name                                                                                                  |
|   **-A** OR **-e**   | Select all processes                                                                                                    |
|        **-f**        | Display full format listing                                                                                             |
|        **-o**        | Specify individual output columns. Can be list. (**comm**, **pmem**, **pcpu**, etc)                                     |
| **--sort** _±column_ | Sort by column. _+_ Sorts ascending. _-_ Sorts by descending                                                            |
|     **--forest**     | Displays processes in a tree format for better child-parent relationship                                                |

```bash
    PID TTY      TIME     CMD  
   2960 pts/0    00:00:00 bash  
   2983 pts/0    00:00:00  \_ ps
```
  
![[ps_sorting.png]]
  
EXAMPLES  
To see every process on the system using standard syntax:  
```bash
ps -e  
ps -ef  
ps -eF  
ps -ely
```

To see every process on the system using BSD syntax:  
```bash
ps ax  
ps axu
```

To print a process tree:  
```bash
ps -ejH  
ps axjf
```

To get info about threads:  
```bash
ps -eLf  
ps axms
```

To get security info:  
```bash
ps -eo euser,ruser,suser,fuser,f,comm,label  
ps axZ  
ps -eM
```

To see every process running as root (real & effective ID) in user format:  
```bash
ps -U root -u root u
```

To see every process with a user-defined format:  
```bash
s -eo pid,tid,class,rtprio,ni,pri,psr,pcpu,stat,wchan:14,comm  
ps axo stat,euid,ruid,tty,tpgid,sess,pgrp,ppid,pid,pcpu,comm  
ps -Ao pid,tt,user,fname,tmout,f,wchan
```

Print only the process IDs of syslogd:  
```bash
ps -C syslogd -o pid=
```

Print only the name of PID 42:  
```bash
ps -q 42 -o comm=
```


# reg
#winCmd #envRecon 

Registry Console Tool

|      Options       |                                                                                   |
|:------------------:| --------------------------------------------------------------------------------- |
| **query** _regkey_ | Returns a list of the next tier of subkeys and entries for requested registry key |


# route
#linuxCmd #networkEnum #networkManipulation

Display and manipulate Routing table info.

\*Note:  Could be possible to add another network to the routing table and connect to it.
	(Ex: You're on a Class C, but can add a Class A (supposedly "segmented") network and connect (proving it's not fully isolated))


# sc
#winCmd #envRecon #serviceRecon #serviceManipulation

Service Control.  Create, start, stop, query, or delete any Windows service.

|   Option   |                                                                        |
|:----------:| ---------------------------------------------------------------------- |
| **config** | Modifies value of a service's entries in the reg & SC Manager database |
| **query**  | Displays more info about the specified service/ driver                 |


# schtasks
#winCmd #envRecon #processes #serviceRecon #serviceManipulation 

List scheduled Windows tasks

| Options |                                                         |
|:-------:| ------------------------------------------------------- |
| **/ru** | Run with perms of a different user or with system perms |
| **/tn** | Filter by TaskName                                      |
| **/u**  | Run w/ the creds of an Admin of the remote computer     |


# scp
#linuxCmd #dataTransfer 

Securely Transfer Files  
  
Relies **ssh** for data transfer. **:** is how **scp** distinguishes btw local and remote locations  
  
Local file to remote system:
```bash
scp [OPTION] file remote_user@IP:/path/to/save
```

Remote file to local system:
```bash
scp [OPTION] remote_user@IP:/remote/file /local/path/to/save
```

Remote file to remote system:
```bash
scp [OPTION] remote1@IP:/remote/file remote2@IP:/path/to/save
```
	* to route traffic through the local machine, add the **-3** option  
  
| Options  |                                                              |
|:--------:| ------------------------------------------------------------ |
|    -P    | Specifies remote host ssh port                               |
| **-p** | Preserves file's modification and access times               |
| **-q** | Suppress the progress meter and non-error messages           |
| **-C** | Forces compressing the data as it's sent to the dest machine |
| **-r** | Copy directories recursively                                 |


# sed
#linuxCmd #textProcessing 

Complex stream editor used to perform basic text transformations on an input stream (a file or input from a pipeline).    
  
[https://catonmat.net/sed-one-liners-explained-part-one](https://catonmat.net/sed-one-liners-explained-part-one)  
  
Invocation:  
```bash
sed <script> <inputfile>
```

| Options |                           |
| ------- | ------------------------- |
| **-e**  | Executes a script         |
| **-i**  | Replace the file in-place |
| g       | Applies the replacement to all matches, not just the first  |

To replace all occurrences of ‘hello’ to ‘world’ in the file input.txt:  
```bash
sed 's/hello/world/' input.txt > output.txt
```
 
To change a UUID of 1001 to 1014:  
```bash
sudo sed -i -e 's/1001/1014/g' /etc/passwd
```


# sort
#linuxCmd #textProcessing 

Sort lines of text files  

| Options |                                                                                                             |
|:-------:| ----------------------------------------------------------------------------------------------------------- |
| **-d**  | Consider only blanks and alphanumeric characters                                                            |
| -**o**  | Write result to ouput file rather than STDOUT                                                               |
| **-n**  | Compare according to string numerical value (useful w/ **uniq -c**)**-r** - Reverse result of comparisons** |
| **-u**  | With -c, check for strict ordering; without -c, output only the first of an equal run                       |


# tail
#linuxCmd #fileProcessing 

Display last 10 (default) lines of a file.  
  
Most often used to monitor log file entries in real time.  

|  Options   |                                                  |
|:----------:| ------------------------------------------------ |
|   **-f**   | Follow. Continually updates output as file grows |
| **-n** _x_ | Changes default line output to _x_               |


# tar
#linuxCmd #fileProcessing 

Compress/ decompress .tar / .tar.gz  
  
| Options |                                                    |
|:-------:| -------------------------------------------------- |
| **-x**  | Extract files from the zipped file                 |
| **-v**  | Verbose mode (lists out the files it's extracting) |
| **-z**  | Decompress files                                   |
| **-f**  | Selects file to work on                            |
| **-c**  | Creates new archive                                |


# tasklist
#winCmd #processes 

Examine Windows processes at the command line

| Options  |                                                                              |
|:--------:| ---------------------------------------------------------------------------- |
| **/fi**  | Filters types of processes to include or exclude (ex: "imagename eq <.exe>") |
|  **/m**  | List all tasks w/ DLL modules loaded (Can use DLL name for query)            |
| **/svc** | List all service info for each process (Maps a service to its process)       |
|  **/v**  | Verbose output                                                               |


# uname
#linuxCmd #envRecon 

Displays basic information about the operating system name and system hardware.  

| Options |                                                                                         |
|:-------:| --------------------------------------------------------------------------------------- |
| **-a**  | Print all information, in the following order, except omit **-p** and **-i** if unknown |
| **-s**  | Print the kernel name                                                                   |
| **-n**  | Print the network node hostname                                                         |
| **-r**  | Print the kernel release                                                                |
| **-v**  | Print the kernel version                                                                |
| **-m**  | Print the machine hardware name                                                         |
| **-p**  | Print the processor type (non-portable)                                                 |
| **-i**  | Print the hardware platform (non-portable)                                              |
| **-o**  | Prints operating-system                                                                 |


# uniq
#linuxCmd #fileProcessing #textProcessing 

Report or omit repeated lines  
  
| Options |                                                |
|:-------:| ---------------------------------------------- |
| **-c**  | Prefixes lines with the number of occurrences  |
| **-d**  | Only print duplicate lines, one for each group |
| **-D**  | Print all duplicate lines                      |
| **-i**  | Ignore case when comparing                     |
| **-u**  | Only print unique lines                        |


# vimdiff
#linuxCmd #fileProcessing 

Opens vim with multiple files, one in each window. The differences between files are highlighted  
  
|   Navigation    |                                                             |
|:------------:| ----------------------------------------------------------- |
|    **do**    | Gets changes from the other window into the current one     |
|    **dp**    | Puts the changes from the current window into the other one |
|   **] c**    | Jumps to the next change                                    |
|   **\[ c**   | Jumps to the previous change                                |
| **Ctrl + W** | Switches to the other split window                          |


# watch
#linuxCmd #processes 

Run a designated command at regular intervals (default every 2 seconds) 

|       Options        |                                                                                                                   |
|:--------------------:| ----------------------------------------------------------------------------------------------------------------- |
|      **-n** _x_      | Changes default interval to _x_ seconds                                                                           |
|        **-e**        | Freeze on command error. Exits on key press                                                                       |
|        **-g**        | Exit when output of command changes                                                                               |
| **-x** OR **--exec** | Pass command to **exec**(2) instead of **sh -c**. Reduces the need to use extra quoting to get the desired effect |
|        **-h**        | Display help and exit                                                                                             |


# wevtuil
#winCmd #envRecon 

Retrieve info about Windows event logs and publishers (Win 7 -10)

|    Options     |                                                                |
|:--------------:| -------------------------------------------------------------- |
|     **/f**     | Format to (ex: **/f:text** )                                   |
| **/if**<\path> | Path to a log file                                             |
|     **qe**     | Query-Events <\path> - Default, provide a log name for <\path> |


# wget
#linuxCmd #dataTransfer 

Downloads files using the HTTP/HTTPS and FTP protocols.  

|     Options     |                                                  |
|:---------------:| ------------------------------------------------ |
|     **-o**      | Allows saving file to given directory/ file name |
|  **--spider**   | Doesn't download the pages                       |
| **--recursive** | Turn on recursive retrieving                     |


# which
#linuxCmd #envRecon #processes 

Searches for given executable within the _$PATH_ environment and displays its full path


# wmic
#winCmd 


# xclip
#linuxCmd #textProcessing 

Cmd line interface w/ the X11 clipboard.    
  
Useful for copying a file's contents to the clipboard:  
```bash
cat file | xclip -selection clipboard
```