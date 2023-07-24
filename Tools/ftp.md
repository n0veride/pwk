

#### File Transfer Protocol  
  
##### Ports:  
	20 - Data  
	21 - Control  
  

##### Passive mode:  
  
###### Linux:  
	passive  
  
###### Win:  
	quote pasv  
  
  
##### Windows:

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
| verbose     | Sets verbose on or off.                                                                                                                                                                                                                                                                                                                   |


##### Linux/ Unix:

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
