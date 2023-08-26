

# 5.7.1
Find all subdomains listed on main megacorpone.com site and their respective ip addresses

“Clumsy”: (Period's are escaped)
```bash
wget www.megacorpone.com  
wc -l index.html  
        316 index.html  
grep "href=" index.html | grep "\.megacorpone" | grep -v "www\.megacorpone\.com" | awk -F "http://" '{print $2}' | cut -d "/" -f 1
```
	support.megacorpone.com">SUPPORT<  
	intranet.megacorpone.com">LOG IN<  
	admin.megacorpone.com  
	intranet.megacorpone.com  
	mail.megacorpone.com  
	mail2.megacorpone.com  
	siem.megacorpone.com  
	support.megacorpone.com  
	syslog.megacorpone.com  
	test.megacorpone.com  
	vpn.megacorpone.com  
	www2.megacorpone.com  
	www2.megacorpone.com  
	www2.megacorpone.com  
	admin.megacorpone.com  
	beta.megacorpone.com  
	beta.megacorpone.com


More elegant way using regex:
```bash
grep -o '[^/]*\.megacorpone\.com' index.html | sort -u > list.txt
```
	admin.megacorpone.com  
	beta.megacorpone.com  
	intranet.megacorpone.com  
	mail2.megacorpone.com  
	mail.megacorpone.com  
	siem.megacorpone.com  
	support.megacorpone.com  
	syslog.megacorpone.com  
	test.megacorpone.com  
	vpn.megacorpone.com  
	www2.megacorpone.com  
	www.megacorpone.com


- **-o** Returns only the string defined by the regex  
- Single quotes treats all enclosed characters literally and doesn't allow for variable expansion.  
- **[^/]*** - Negated (**^**) set (**[ ]**) which searches for any number of characters (*****) not including forward-slash  
- Periods are escaped with a back-slash reinforcing we're looking for a literal period.  
  
  
Ex: **\[^/,"\]*** - excludes both forward-slash and double-quote characters  
  
  
To then find each url's ip address:
```bash
for url in $(cat list.txt); do host $url; done
```
	admin.megacorpone.com has address 51.222.169.208  
	beta.megacorpone.com has address 51.222.169.209  
	intranet.megacorpone.com has address 51.222.169.211  
	mail2.megacorpone.com has address 51.222.169.213  
	mail.megacorpone.com has address 51.222.169.212  
	siem.megacorpone.com has address 51.222.169.215  
	support.megacorpone.com has address 51.222.169.218  
	syslog.megacorpone.com has address 51.222.169.217  
	test.megacorpone.com has address 51.222.169.219  
	vpn.megacorpone.com has address 51.222.169.220  
	www2.megacorpone.com has address 149.56.244.87  
	www.megacorpone.com has address 149.56.244.87


Cut just the ip addys:
```bash
for url in $(cat list.txt); do host $url; done | cut -d “ ” -f 4 | sort -u
```
	149.56.244.87  
	51.222.169.208  
	51.222.169.209  
	51.222.169.211  
	51.222.169.212  
	51.222.169.213  
	51.222.169.215  
	51.222.169.217  
	51.222.169.218  
	51.222.169.219  
	51.222.169.220



# 5.7.2
Search for an exploit that begins with “afd” on [www.exploit-db.com](http://www.exploit-db.com) to help with privexec on a Windows box during a pentest

```bash
searchsploit afd windows -w -t
```
	 Exploit Title                             |  URL  
	Microsoft Windows (x86) - 'afd.sys' Privil | https://www.exploit-db.com/exploits/40564  
	Microsoft Windows - 'AfdJoinLeaf' Privileg | https://www.exploit-db.com/exploits/21844  
	Microsoft Windows - 'afd.sys' Local Kernel | https://www.exploit-db.com/exploits/18755  
	Microsoft Windows 7 (x64) - 'afd.sys' Dang | https://www.exploit-db.com/exploits/39525  
	Microsoft Windows 7 (x86) - 'afd.sys' Dang | https://www.exploit-db.com/exploits/39446  
	Microsoft Windows 7 Kernel - Pool-Based Ou | https://www.exploit-db.com/exploits/42009  
	Microsoft Windows XP - 'afd.sys' Local Ker | https://www.exploit-db.com/exploits/17133  
	Microsoft Windows XP/2003 - 'afd.sys' Priv | https://www.exploit-db.com/exploits/6757  
	Microsoft Windows XP/2003 - 'afd.sys' Priv | https://www.exploit-db.com/exploits/18176  


Cut down to just urls:  
```bash
searchsploit afd windows -w -t | cut -d “|" -f 2
```
	https://www.exploit-db.com/exploits/40564  
	https://www.exploit-db.com/exploits/21844  
	https://www.exploit-db.com/exploits/18755  
	https://www.exploit-db.com/exploits/39525  
	https://www.exploit-db.com/exploits/39446  
	https://www.exploit-db.com/exploits/42009  
	https://www.exploit-db.com/exploits/17133  
	https://www.exploit-db.com/exploits/18176  
	https://www.exploit-db.com/exploits/6757

Download raw exploit from website:
```bash
for e in $(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|"); do exp_name=$(echo $e | cut -d "/" -f 5) && url=$(echo $e | sed 's/exploits/raw/') && wget -q --no-check-certificate $url -O $exp_name; done
```

- Iterates through the SearchSploit URLs we grabbed  
- Inside the loop, set **exp_name** to the “name” of the exploit (using grep, cut, and command substitution) and set **url** to the raw download location (again with sed and command substitution)  
- If that is successful (&&), grab the exploit with wget (in quiet mode with no certificate check) saving it locally with the exploit name as the local file name.  
  
Putting it in a bash script:  
```bash
#!/bin/bash  
# Bash script to search for a given exploit and download all matches.  
  
for e in $(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|")  
  
do  
  exp_name=$(echo $e | cut -d "/" -f 5)  
  url=$(echo $e | sed 's/exploits/raw/')  
  wget -q --no-check-certificate $url -O $exp_name  
done
```



# 5.7.3
View nmap scan results (port 80 w/in an ip range) as HTML results  
```bash
mkdir tmp && cd tmp  
sudo nmap -A -p80 --open 10.1.11.0/24 -oG nmap-scan_10.1.11.0-254  
cat nmap-scan_10.1.11.0-254
```
	# Nmap 7.60 scan initiated Sun Mar 18 18:57:48 2019 as: nmap -A -p80 --open -oG nmap-  
	scan_10.11.1.0-254 10.11.1.0/24  
	Host: 10.11.1.8 ()  Status: Up  
	Host: 10.11.1.8 ()  Ports: 80/open/tcp//http//Apache httpd 2.0.52 ((CentOS))/   Seq  
	Index: 197  IP ID Seq: All zeros  
	Host: 10.11.1.10 () Status: Up  
	Host: 10.11.1.10 () Ports: 80/open/tcp//http//Microsoft IIS httpd 6.0/  Seq Index: 256  
	IP ID Seq: Incremental  
	Host: 10.11.1.13 () Status: Up  
	Host: 10.11.1.13 () Ports: 80/open/tcp//http//Microsoft IIS httpd 5.1/  Seq Index: 136  
	IP ID Seq: Incremental  
	...


Extract just IP addresses:  
```bash
grep 80 nmap-scan_10.11.1.0-254 | grep -v "Nmap" | awk '{print $2}'
```

Bash one-liner to loop through IPs and use [cutycapt](PWK--Tools--cutycapt.html) saving each ip's html image to an individual file:
```bash
for ip in $(grep 80 nmap-scan_10.11.1.0-254 | grep -v "Nmap" | awk '{print $2}'); do cutycapt --url=$ip --out=$ip.png;done  
ls -1 *.png
```
	10.11.1.10.png  
	10.11.1.115.png  
	10.11.1.116.png  
	10.11.1.128.png  
	10.11.1.13.png  
	10.11.1.133.png  
	10.11.1.14.png  
	10.11.1.202.png  
	10.11.1.209.png  
	10.11.1.217.png  
	...


Build an HTML file (web.html), starting with the most basic tags. Then, the **ls** and **awk** statements insert each .PNG file name into an HTML IMG tag and append this to our web.html  
```bash
cat > pngtohtml.sh  
#!/bin/bash  
# Bash script to examine the scan results through HTML.  
  
echo "<HTML><BODY><BR>" > web.html  
  
ls -1 *.png | awk -F : '{ print $1":\n<BR><IMG SRC=\""$1""$2"\" width=600><BR>"}' >> web.html  
  
echo "</BODY></HTML>" >> web.html  
  
<ctrl + D>  
  
chmod +x pngtohtml.sh  
./pngtohtml.sh  
firefox web.html
```