
Used for tunneling and port forwarding.  
  
Installed by Default on Win.  
  
REQUIRES _IP Helper Service_ running & _IPv6_ enabled.

Usage:
```powershell
PS C:\Windows\system32> netsh
	netsh>/?
```


Port forwarding:
	Ex:
```powershell
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=9000 connectaddress=192.168.0.1 connectport=80
```
	**interface** - **portproxy**
	**add / delete** - **v4tov4**
	**listenaddress=** - Local/ pivot endpoint IP **0.0.0.0**
	**listenport=** - Port pivot endpoint is listening on
	**connectaddress=** - Remote IP of next victim
	**connectport=** - Port next victim endpoint is listening on


The following commands are available:

Commands in this context:
**..**            - Goes up one context level.
**?**             - Displays a list of commands.
**abort**         - Discards changes made while in offline mode.
**add**           - Adds a configuration entry to a list of entries.
**advfirewall**   - Changes to the \`netsh advfirewall' context.
	**advfirewall show currentprofile** - Examine detailed built-in firewall settings (Win 7-10)
**alias**         - Adds an alias.
**branchcache**   - Changes to the \`netsh branchcache' context.
**bridge**        - Changes to the \`netsh bridge' context.
**bye**           - Exits the program.
**commit**        - Commits changes made while in offline mode.
**delete**        - Deletes a configuration entry from a list of entries.
**dhcpclient**    - Changes to the \`netsh dhcpclient' context.
**dnsclient**     - Changes to the \`netsh dnsclient' context.
**dump**          - Displays a configuration script.
**exec**          - Runs a script file.
**exit**          - Exits the program.
**firewall**      - Changes to the \`netsh firewall' context.
**help**          - Displays a list of commands.
**http**          - Changes to the \`netsh http' context.
**interface**     - Changes to the \`netsh interface' context.
**ipsec**         - Changes to the \`netsh ipsec' context.
**ipsecdosprotection** - Changes to the \`netsh ipsecdosprotection' context.
**lan**           - Changes to the \`netsh lan' context.
**namespace**     - Changes to the \`netsh namespace' context.
**netio**         - Changes to the \`netsh netio' context.
**offline**       - Sets the current mode to offline.
**online**        - Sets the current mode to online.
**popd**          - Pops a context from the stack.
**pushd**         - Pushes current context on stack.
**quit**          - Exits the program.
**ras**           - Changes to the \`netsh ras' context.
**rpc**           - Changes to the \`netsh rpc' context.
**set**           - Updates configuration settings.
**show**          - Displays information.
**trace**         - Changes to the \`netsh trace' context.
	**trace** - Used for packet capture.  File will save in ETL format & will need to be converted to .pcap-ng
``` powershell
netsh trace start capture=yes maxsize=1000 tracefile=filename.etl
```
**unalias**       - Deletes an alias.
**wfp**           - Changes to the \`netsh wfp' context.
**winhttp**       - Changes to the \`netsh winhttp' context.
**winsock**       - Changes to the \`netsh winsock' context.

The following sub-contexts are available:
 advfirewall branchcache bridge dhcpclient dnsclient firewall http interface ipsec ipsecdosprotection lan namespace netio ras rpc trace wfp winhttp winsock

To view help for a command, type the command, followed by a space, and then type ?.