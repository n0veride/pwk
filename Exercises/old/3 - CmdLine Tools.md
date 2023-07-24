
###### 3.3.5
grep, cut, sort, uniq

```bash
head access.log   
201.21.152.44 - - [25/Apr/2013:14:05:35 -0700] "GET /favicon.ico HTTP/1.1" 404 89 "-"   
"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.31 (KHTML, like Gecko)   
Chrome/26.0.1410.64 Safari/537.31" "random-site.com"   
70.194.129.34 - - [25/Apr/2013:14:10:48 -0700] "GET /include/jquery.jshowoff.min.js   
HTTP/1.1" 200 2553 "http://www.random-site.com/" "Mozilla/5.0 (Linux; U; Android   
4.1.2; en-us; SCH-I535 Build/JZO54K) AppleWebKit/534.30 (KHTML, like Gecko)   
Version/4.0 Mobile Safari/534.30" "www.random-site.com"


wc -l access.log   
	1173 access.log


cat access.log | cut -d " " -f 1 | sort -u   
	201.21.152.44   
	208.115.113.91   
	208.54.80.244   
	208.68.234.99   
	70.194.129.34   
	72.133.47.242   
	88.112.192.2   
	98.238.13.253   
	99.127.177.95


cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn   
	1038 208.68.234.99   
	59 208.115.113.91   
	22 208.54.80.244   
	21 99.127.177.95   
	8 70.194.129.34   
	1 201.21.152.44


cat access.log | grep '208.68.234.99' | cut -d "\"" -f 2 | uniq -c   
	1038 GET //admin HTTP/1.1


cat access.log | grep '208.68.234.99' | grep '/admin ' | sort -u   
208.68.234.99 - - [22/Apr/2013:07:51:20 -0500] "GET //admin HTTP/1.1" 401 742 "-" "Teh Forest Lobster"   
208.68.234.99 - admin [22/Apr/2013:07:51:25 -0500] "GET //admin HTTP/1.1" 200 575 "-" "Teh Forest Lobster"
```



###### 3.3.5.1.1
Using /etc/passwd, extract the user and home directory fields for all users on your Kali machine for which the shell is set to /bin/false.

```bash
grep "/bin/false" /etc/passwd | cut -f 1,6 -d ":"  
	tss:/var/lib/tpm  
	whoopsie:/nonexistent  
	sddm:/var/lib/sddm  
	hplip:/run/hplip
```


###### 3.3.5.1.2
Use cat in a one-liner to print the output of the /etc/passwd and replace all instances of the “nonexistent” string with “nerp”.

```bash
grep nonexistent /etc/passwd | sed 's/nonexistent/nerp/'  
nobody:x:65534:65534:nobody:/nerp:/usr/sbin/nologin  
messagebus:x:103:106::/nerp:/usr/sbin/nologin  
_apt:x:105:65534::/nerp:/usr/sbin/nologin  
tcpdump:x:108:115::/nerp:/usr/sbin/nologin  
whoopsie:x:115:121::/nerp:/bin/false
```