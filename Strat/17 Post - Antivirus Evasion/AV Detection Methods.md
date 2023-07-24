

### Detection Methods:
Since antivirus software vendors use different signatures and proprietary tech for detection,  
and each vendor updates their databases constantly, it's usually difficult to come up with a catch-all antivirus evasion solution.  
Quite often, this process is based on a trial-and-error approach in a test environment.  
  
So, ID the presence, type, & version of the deployed antivirus software before considering a bypass strategy.  
  
If the client network or system implements antivirus software, we should gather as much information as possible  
and replicate the configuration in a lab environment for AV bypass testing before uploading files to the target machine.  
  
  
  
#### Signature-based:  
Detects based on continuous sequence of bytes w/in the malware that uniquely ID's it.  
- Blocklisting  
- Easy to bypass by changing/ obfuscating the contents (Poss Ex: changing upper to lowercase)  
  
  
#### Heuristic-based:  
Relies on various rules & algorithms to determine whether or not an action is considered malicious.  
- Steps through instruction set or attempts to decompile & looks for malicious patterns/ program calls  
- Doesn't rely on signatures so can detect Unknown or altered KM  
  
  
#### Behavior-based:  
Dynamically analyzes the behavior of the file.  
- Executes w/in an emulated env & looks for malicious actions  
- Doesn't rely on signatures so can detect Unknown or altered KM