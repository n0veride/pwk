

[https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)  
  
Web-based apps usually expose a large attack surface because of a lack of mature application code, multiple dependencies, and insecure server configs  
  
We should always gather info on the web app:  
• What does the app do?  
• What language is it written in?  
• What server software is the app running on?  
  
  
[Web App Enumeration & Tools](9.2%20-%20Web%20App%20Enum.md)  
  
[Admin Consoles](9.4.1%20-%20Admin%20Consoles.md)  
  
[Burp Suite](BurpSuite.md)  
  
[XSS](9.4.2%20-%20XSS.md)  
  
[Directory Traversal](9.4.3%20-%20Directory%20Traversal.md)  

[File Inclusion](9.4.4%20-%20File%20Inclusion.md)  

[SQL Injection](9.4.5%20-%20SQLi.md)  
  

Some things to consider when attempting to bypass login prompts:  
  
Like below, login forms can include tokens to prevent brute forcing and other attacks.  
  
We can also see that the form sets a _set_session_ parameter which is unique for each request.  
If we change the _set_session_ parameter or _token_ parameter and they don't match the values of the _phpMyAdmin_ cookie, the site will return an error:
![[login_token.png]]

We can use BurpSuite's Intruder to overcome this protective measure & ensure the values match.