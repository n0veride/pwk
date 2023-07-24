
Tool for enumerating information from Windows and Samba systems.  
Written in PERL and is basically a wrapper around the Samba tools **smbclient**, **rpclient**, **net**, and **nmblookup**  
  
**-a** - Do all simple enumeration (-U -S -G -P -r -o -n -i). Default  
**-U** - Get userlist  
**-M** - Get machine list*  
**-S** - Get sharelist  
**-P** - Get password policy information  
**-G** - Get group and member list  
**-d** - Be detailed, applies to -U and -S  
**-u** _\<user\>_ - Specify username to use (default "")  
**-p** _\<pass\>_ - Specify password to use (default "")  
**-v** - Verbose. Shows full commands being run (net, rpcclient, etc.)  
**-o** - Get OS information  
**-i** - Get printer information  
  
The following options from enum.exe aren't implemented: -L, -N, -D, -f  
  
Additional options:  
**-r** - Enumerate users via RID cycling  
**-R** _\<range\>_ - RID ranges to enumerate (default: 500-550,1000-1050, implies -r)  
**-K** _\<n\>_ - Keep searching RIDs until _n_ consective RIDs don't correspond to a username. Impies RID range ends at 999999. Useful against DCs.  
**-l** - Get some (limited) info via LDAP 389/TCP (for DCs only)  
**-s** _\<filename\>_ - Brute force guessing for share names  
**-k** _\<user\>_ User(s) that exists on remote system (default: administrator,guest,krbtgt,domain admins,root,bin,none).  
Used to get sid with "lookupsid known_username"  
Use commas to try several users: "-k admin,user1,user2"  
**-w** _\<wrkg\>_ - Specify workgroup manually (usually found automatically)  
**-n** - Do an nmblookup (similar to nbtstat)