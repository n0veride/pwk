

Shellcode injection tool capable of bypassing AntiVirus apps.  
  
** Requires **wine32**  
** Compatible ONLY w/ [x86 architecture](x86%20Architecture.md)  
  
  
Performs a thorough analysis of the target PE file and the execution paths.  
It then determines where it can inject our shellcode, without relying on traditional injection techniques that are easily caught by AV engines.  
Including changing of PE file section permissions, creating new sections, and so on.  
Finally, Shellter attempts to use the existing [PE Import Address Table](Portable%20Executable.md) (IAT) entries to locate functions that will be used for the memory allocation, transfer, and execution of our payload.  
  
Shellter obfuscates both the payload as well as the payload decoder before injecting them into the PE  
  
  
**Operation:**  
Mode - Auto & Manual.  
Manual allows us to adjust options with much more granularity  
PE Target - Requires full path to binary  
Creates a backup of binary first  
Stealth Mode - Attempts to restore the execution flow after the payload is executed  
Custom payloads need to terminate by exiting the current thread.  
Payload Options - Choice of listed or custom payload  
For Listed, need to select ‘L’, then payload index.  
  
  

### Tips & Tricks

• **Find a few 32-bit standalone legitimate executables** that always work for you and stick with them for as long as they do the job.  
However, take in serious consideration what is discussed in this [article](https://www.shellterproject.com/an-important-tip-for-shellter-usage/), thus avoid using executables of popular applications when not needed.  
Unless you are using the Steath Mode for a RedTeam job because you want to trick the victim to run a specific backdoored application, there is no reason to use a different executable every time. Just make sure you use a clean one.  
  
◇ Before using a legitimate executable, try to scan it using an online multi-AV scanner. Sometimes **AVs do produce false positives**, so it’s good to know that your chosen executable wasn’t detected as something malicious in the first place.  
  
◇ **Don’t use packed executables!**  
If you get a notification that the executable is probably packed, then get another one.  
  
◇ **Don’t use Shellter with executables produced by other pentesting tools or frameworks.** These have possibly been flagged already by many AV vendors. Since Shellter actually traces the execution flow of the target application, you also risk to ‘infect’ yourself if you do that.  
  
◇ **If you just need to execute your payload during a pentesting job, you don’t need to enable the Stealth mode feature.** This feature is useful during Red Team engagements, since it enables Shellter to maintain the original functionality of the infected application.  
  
◇ **If you decide to use the Dynamic Thread Context Keys (DTCK) feature then try to avoid enabling obfuscation for every single step.** This feature enables an extra filtering stage which reduces even more the available injection locations, so it’s better not to increase a lot the size of the code to be injected.  
So as a rule of thumb, in this case just choose to obfuscate the IAT handler. If you use command line just add ‘––polyIAT’ and don’t enable any other obfuscation features.  
  
◇ **If you want to inject a DLL with a reflective loader, try to keep your DLL as small as possible** and use an executable that has a section, where the code has been traced, that can fit it.  
Think before you do!  
  
◇ If you are not sure about how to use Shellter, and what each feature does, then **use the Auto Mode**. It has been put there for this purpose. Use it!  
  
◇ **If you are just interested in bypassing the AV and execute your payload,** hence not looking at the Stealth Mode feature, then **various uninstallers dropped by installed programs might be what you need**.  
These are generally standalone and small in size, which makes them perfect for generic usage.  
  
◇ **If you really want to use the Manual Mode, make sure you understand enough what each feature does.** Reading the documentation about Shellter is also something you should do first.  
  
◇ **If you use the Manual Mode, don’t just trace for a very small number of instructions.** The point and one of the unique features of Shellter are it’s ability to trace down the execution flow so that it doesn’t inject into predictable locations. Don’t ruin it for yourself.  
Usually, 50k instructions should be fine, but as you go deeper in the execution flow the better it gets.  
If you think that reaching the amount of instructions that you chose it takes too long, you can always interrupt the tracing stage by pressing CTRL+C and proceed with the rest of the injection process.  
  
**PS: Shellter tries its best to avoid any mistakes while completely automating the process of dynamic PE infection.  
However, this is a complicated task and for that reason there is always a small possibility for failure.  
Following the list of tips and tricks presented here, will give you a good starting point for using Shellter.  
Keep in mind that while Shellter will try to handle everything for you, it does need your common sense to give you its best.**