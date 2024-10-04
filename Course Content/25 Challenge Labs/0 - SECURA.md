Three-machine enterprise environment

## Objectives
- Exploit vulnerabilities in ManageEngine
- Pivot through internal services
- Leverage insecure GPO permissions to escalate privileges
- Compromise the domain

# 192.168.159.95

## Nmap Scan

```bash
nmap -v -sV -sC -p 135,139,445,5001,5040,5985,8443,12000,44444,47001,49664-49672,54233,54234,57499,57528 -oN 95/open_sVsC.txt 192.168.159.95

Nmap scan report for 192.168.159.95
PORT      STATE SERVICE         VERSION
135/tcp   open  msrpc           Microsoft Windows RPC
139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5001/tcp  open  commplex-link?
| fingerprint-strings: 
|   SIPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html; charset=ISO-8859-1
|     Content-Length: 132
|_    MAINSERVER_RESPONSE:<serverinfo method="setserverinfo" mainserver="5001" webserver="44444" pxyname="192.168.45.151" startpage=""/>
5040/tcp  open  unknown
5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open  ssl/https-alt   AppManager
|_ssl-date: 2024-10-04T21:10:47+00:00; +23s from scanner time.
| http-methods: 
|_  Supported Methods: GET POST
|_http-title: Site doesn''t have a title (text/html).
|_http-favicon: Unknown favicon MD5: CF9934E74D25878ED70B430915D931ED
| ssl-cert: Subject: commonName=APPLICATIONSMANAGER/organizationName=WebNMS/stateOrProvinceName=Pleasanton/countryName=US
| Issuer: commonName=APPLICATIONSMANAGER/organizationName=WebNMS/stateOrProvinceName=Pleasanton/countryName=US
| Public Key type: rsa
| Public Key bits: 2072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-02-27T11:03:03
| Not valid after:  2050-02-27T11:03:03
| MD5:   094c:a4e7:2020:ec73:1e9f:e5ed:e0ea:5939
|_SHA-1: 834c:a871:c377:20d8:49bd:73d4:0660:b8a8:9a6a:df17
|_http-server-header: AppManager
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Set-Cookie: JSESSIONID_APM_44444=D241E712005F1007093B06D49B69E9E7; Path=/; Secure; HttpOnly
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 973
|     Date: Fri, 04 Oct 2024 21:06:59 GMT
|     Connection: close
|     Server: AppManager
|     <!DOCTYPE html>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     <!-- Includes commonstyle CSS and dynamic style sheet bases on user selection -->
|     <link href="/images/commonstyle.css?rev=14440" rel="stylesheet" type="text/css">
|     <link href="/images/newUI/newCommonstyle.css?rev=14260" rel="stylesheet" type="text/css">
|     <link href="/images/Grey/style.css?rev=14030" rel="stylesheet" type="text/css">
|     <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
|     </head>
|     <body bgcolor="#FFFFFF" leftmarg
|   GetRequest: 
|     HTTP/1.1 200 
|     Set-Cookie: JSESSIONID_APM_44444=BFF7138A476CEFB2A186528223679C18; Path=/; Secure; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Fri, 04 Oct 2024 21:06:59 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Set-Cookie: JSESSIONID_APM_44444=12DFCD8A8B51EC270867F1E23B775B74; Path=/; Secure; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Fri, 04 Oct 2024 21:06:59 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|_    margin: 0; color:#000;
12000/tcp open  cce4x?
44444/tcp open  cognex-dataman?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Set-Cookie: JSESSIONID_APM_44444=269CC0F0F745522FEB8406F313710AC3; Path=/; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Fri, 04 Oct 2024 21:06:58 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Set-Cookie: JSESSIONID_APM_44444=A2AA78F5BA17BB7A1A13F6711221ECEC; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Fri, 04 Oct 2024 21:06:58 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|     margin: 0; color:#000;
|     font-
|   RTSPRequest: 
|     HTTP/1.1 505 
|     vary: accept-encoding
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 2142
|     Date: Fri, 04 Oct 2024 21:06:58 GMT
|     Server: AppManager
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|_    HTTP Version Not Supported</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#
47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc           Microsoft Windows RPC
49665/tcp open  msrpc           Microsoft Windows RPC
49666/tcp open  msrpc           Microsoft Windows RPC
49667/tcp open  msrpc           Microsoft Windows RPC
49668/tcp open  msrpc           Microsoft Windows RPC
49669/tcp open  msrpc           Microsoft Windows RPC
49670/tcp open  msrpc           Microsoft Windows RPC
49671/tcp open  msrpc           Microsoft Windows RPC
49672/tcp open  tcpwrapped
54233/tcp open  unknown
| fingerprint-strings: 
|   SMBProgNeg, X11Probe: 
|_    CLOSE_SESSION
54234/tcp open  unknown
| fingerprint-strings: 
|   SMBProgNeg, X11Probe: 
|_    CLOSE_SESSION
57499/tcp open  java-rmi        Java RMI
57528/tcp open  unknown
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5001-TCP:V=7.94SVN%I=7%D=10/4%Time=67005938%P=x86_64-pc-linux-gnu%r
SF:(SIPOptions,DB,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html;\x
SF:20charset=ISO-8859-1\r\nContent-Length:\x20132\r\n\r\nMAINSERVER_RESPON
SF:SE:<serverinfo\x20method=\"setserverinfo\"\x20mainserver=\"5001\"\x20we
SF:bserver=\"44444\"\x20pxyname=\"192\.168\.45\.151\"\x20startpage=\"\"/>\
SF:n\0\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.94SVN%T=SSL%I=7%D=10/4%Time=670058DC%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,24E,"HTTP/1\.1\x20200\x20\r\nSet-Cookie:\x20JSESSIONI
SF:D_APM_44444=BFF7138A476CEFB2A186528223679C18;\x20Path=/;\x20Secure;\x20
SF:HttpOnly\r\nAccept-Ranges:\x20bytes\r\nETag:\x20W/\"261-1591621693000\"
SF:\r\nLast-Modified:\x20Mon,\x2008\x20Jun\x202020\x2013:08:13\x20GMT\r\nC
SF:ontent-Type:\x20text/html\r\nContent-Length:\x20261\r\nDate:\x20Fri,\x2
SF:004\x20Oct\x202024\x2021:06:59\x20GMT\r\nConnection:\x20close\r\nServer
SF::\x20AppManager\r\n\r\n<!--\x20\$Id\$\x20-->\n<!DOCTYPE\x20HTML\x20PUBL
SF:IC\x20\"-//W3C//DTD\x20HTML\x204\.01\x20Transitional//EN\">\n<html>\n<h
SF:ead>\n<!--\x20This\x20comment\x20is\x20for\x20Instant\x20Gratification\
SF:x20to\x20work\x20applications\.do\x20-->\n<script>\n\n\twindow\.open\(\
SF:"/webclient/common/jsp/home\.jsp\",\x20\"_top\"\);\n\n</script>\n\n</he
SF:ad>\n</html>\n")%r(HTTPOptions,849,"HTTP/1\.1\x20403\x20\r\nSet-Cookie:
SF:\x20JSESSIONID_APM_44444=12DFCD8A8B51EC270867F1E23B775B74;\x20Path=/;\x
SF:20Secure;\x20HttpOnly\r\nCache-Control:\x20private\r\nExpires:\x20Thu,\
SF:x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;c
SF:harset=UTF-8\r\nContent-Length:\x201810\r\nDate:\x20Fri,\x2004\x20Oct\x
SF:202024\x2021:06:59\x20GMT\r\nConnection:\x20close\r\nServer:\x20AppMana
SF:ger\r\n\r\n<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge
SF:\">\n<meta\x20http-equiv=\"Content-Type\"\x20content=\"UTF-8\">\n<!--\$
SF:Id\$-->\n\n\n\n\n\n\n\n\n\n<html>\n<head>\n<title>Applications\x20Manag
SF:er</title>\n\n<link\x20REL=\"SHORTCUT\x20ICON\"\x20HREF=\"/favicon\.ico
SF:\">\n\n</head>\n\n<body\x20style=\"background-color:#fff;\">\n\n<style\
SF:x20type=\"text/css\">\n\t#container-error\n\t{\n\t\tborder:1px\x20solid
SF:\x20#c1c1c1;\n\t\tbackground:\x20#fff;\x20font:11px\x20Arial,\x20Helvet
SF:ica,\x20sans-serif;\x20width:90%;\x20margin:80px;\n\t\x20\t\n\t}\n\n\t#
SF:header-error\n\t{\n\t\tbackground:\x20#ededed;\x20line-height:18px;\n\t
SF:\tpadding:\x2015px;\x20color:#000;\x20font-size:8px;\n\t}\n\n\t#header-
SF:error\x20h1\n\t{\n\t\tmargin:\x200;\x20\x20color:#000;")%r(FourOhFourRe
SF:quest,4C3,"HTTP/1\.1\x20404\x20\r\nSet-Cookie:\x20JSESSIONID_APM_44444=
SF:D241E712005F1007093B06D49B69E9E7;\x20Path=/;\x20Secure;\x20HttpOnly\r\n
SF:Content-Type:\x20text/html;charset=UTF-8\r\nContent-Length:\x20973\r\nD
SF:ate:\x20Fri,\x2004\x20Oct\x202024\x2021:06:59\x20GMT\r\nConnection:\x20
SF:close\r\nServer:\x20AppManager\r\n\r\n<!DOCTYPE\x20html>\n\n<meta\x20ht
SF:tp-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\">\n\n\n\n\n\n\n\n\n\
SF:n\n<html>\n<head>\n<title>Applications\x20Manager</title>\n\n<link\x20R
SF:EL=\"SHORTCUT\x20ICON\"\x20HREF=\"/favicon\.ico\">\n\n<!--\x20Includes\
SF:x20commonstyle\x20CSS\x20and\x20dynamic\x20style\x20sheet\x20bases\x20o
SF:n\x20user\x20selection\x20-->\n\n<link\x20href=\"/images/commonstyle\.c
SF:ss\?rev=14440\"\x20rel=\"stylesheet\"\x20type=\"text/css\">\n\n\x20\x20
SF:\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\x20<link\x20hr
SF:ef=\"/images/newUI/newCommonstyle\.css\?rev=14260\"\x20rel=\"stylesheet
SF:\"\x20type=\"text/css\">\n\x20\x20\x20\x20\n\n<link\x20href=\"/images/G
SF:rey/style\.css\?rev=14030\"\x20rel=\"stylesheet\"\x20type=\"text/css\">
SF:\n\n<meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;\x20cha
SF:rset=iso-8859-1\">\n</head>\n\n<body\x20bgcolor=\"#FFFFFF\"\x20leftmarg
SF:");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port44444-TCP:V=7.94SVN%I=7%D=10/4%Time=670058DA%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,246,"HTTP/1\.1\x20200\x20\r\nSet-Cookie:\x20JSESSIONID_APM
SF:_44444=269CC0F0F745522FEB8406F313710AC3;\x20Path=/;\x20HttpOnly\r\nAcce
SF:pt-Ranges:\x20bytes\r\nETag:\x20W/\"261-1591621693000\"\r\nLast-Modifie
SF:d:\x20Mon,\x2008\x20Jun\x202020\x2013:08:13\x20GMT\r\nContent-Type:\x20
SF:text/html\r\nContent-Length:\x20261\r\nDate:\x20Fri,\x2004\x20Oct\x2020
SF:24\x2021:06:58\x20GMT\r\nConnection:\x20close\r\nServer:\x20AppManager\
SF:r\n\r\n<!--\x20\$Id\$\x20-->\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//
SF:DTD\x20HTML\x204\.01\x20Transitional//EN\">\n<html>\n<head>\n<!--\x20Th
SF:is\x20comment\x20is\x20for\x20Instant\x20Gratification\x20to\x20work\x2
SF:0applications\.do\x20-->\n<script>\n\n\twindow\.open\(\"/webclient/comm
SF:on/jsp/home\.jsp\",\x20\"_top\"\);\n\n</script>\n\n</head>\n</html>\n")
SF:%r(HTTPOptions,841,"HTTP/1\.1\x20403\x20\r\nSet-Cookie:\x20JSESSIONID_A
SF:PM_44444=A2AA78F5BA17BB7A1A13F6711221ECEC;\x20Path=/;\x20HttpOnly\r\nCa
SF:che-Control:\x20private\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:
SF:00:00\x20GMT\r\nContent-Type:\x20text/html;charset=UTF-8\r\nContent-Len
SF:gth:\x201810\r\nDate:\x20Fri,\x2004\x20Oct\x202024\x2021:06:58\x20GMT\r
SF:\nConnection:\x20close\r\nServer:\x20AppManager\r\n\r\n<meta\x20http-eq
SF:uiv=\"X-UA-Compatible\"\x20content=\"IE=edge\">\n<meta\x20http-equiv=\"
SF:Content-Type\"\x20content=\"UTF-8\">\n<!--\$Id\$-->\n\n\n\n\n\n\n\n\n\n
SF:<html>\n<head>\n<title>Applications\x20Manager</title>\n\n<link\x20REL=
SF:\"SHORTCUT\x20ICON\"\x20HREF=\"/favicon\.ico\">\n\n</head>\n\n<body\x20
SF:style=\"background-color:#fff;\">\n\n<style\x20type=\"text/css\">\n\t#c
SF:ontainer-error\n\t{\n\t\tborder:1px\x20solid\x20#c1c1c1;\n\t\tbackgroun
SF:d:\x20#fff;\x20font:11px\x20Arial,\x20Helvetica,\x20sans-serif;\x20widt
SF:h:90%;\x20margin:80px;\n\t\x20\t\n\t}\n\n\t#header-error\n\t{\n\t\tback
SF:ground:\x20#ededed;\x20line-height:18px;\n\t\tpadding:\x2015px;\x20colo
SF:r:#000;\x20font-size:8px;\n\t}\n\n\t#header-error\x20h1\n\t{\n\t\tmargi
SF:n:\x200;\x20\x20color:#000;\n\t\tfont-")%r(RTSPRequest,912,"HTTP/1\.1\x
SF:20505\x20\r\nvary:\x20accept-encoding\r\nContent-Type:\x20text/html;cha
SF:rset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x202142\r\nDat
SF:e:\x20Fri,\x2004\x20Oct\x202024\x2021:06:58\x20GMT\r\nServer:\x20AppMan
SF:ager\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x2
SF:0Status\x20505\x20\xe2\x80\x93\x20HTTP\x20Version\x20Not\x20Supported</
SF:title><style\x20type=\"text/css\">h1\x20{font-family:Tahoma,Arial,sans-
SF:serif;color:white;background-color:#525D76;font-size:22px;}\x20h2\x20{f
SF:ont-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76
SF:;font-size:16px;}\x20h3\x20{font-family:Tahoma,Arial,sans-serif;color:w
SF:hite;background-color:#525D76;font-size:14px;}\x20body\x20{font-family:
SF:Tahoma,Arial,sans-serif;color:black;background-color:white;}\x20b\x20{f
SF:ont-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76
SF:;}\x20p\x20{font-family:Tahoma,Arial,sans-serif;background:white;color:
SF:black;font-size:12px;}\x20a\x20{color:black;}\x20a\.name\x20{color:blac
SF:k;}\x20\.line\x20{height:1px;background-color:#");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port54233-TCP:V=7.94SVN%I=7%D=10/4%Time=67005912%P=x86_64-pc-linux-gnu%
SF:r(SMBProgNeg,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(X11Prob
SF:e,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port54234-TCP:V=7.94SVN%I=7%D=10/4%Time=67005912%P=x86_64-pc-linux-gnu%
SF:r(SMBProgNeg,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(X11Prob
SF:e,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 23s, deviation: 0s, median: 22s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-10-04T21:09:28
|_  start_date: N/A
```

# 192.168.159.96


# 192.168.159.97