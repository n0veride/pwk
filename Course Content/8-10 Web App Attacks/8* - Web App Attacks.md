

[https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)  
  
Web-based apps usually expose a large attack surface due to multiple dependencies, insecure server configurations, a lack of mature application code, and business-specific application flaws  
  
We should always gather info on the web app:  
• What does the app do?  
• What language is it written in?  
• What server software is the app running on?


## CGI
Common Gateway Interface

- Interface specification that enables web servers to execute an external program, usually to process user requests.
- Sorta similar to API
- Initial mechanism used to make websites interact with databases and other applications.
- Can be abused for Shellshock

## CMS

- Has front-end user interface allowing user to add, modify, and removal of content from a site w/o need of a webmaster
- A delivery app that compiles the content and updates the site.
- Presents patching challenge.

Common CMS apps:
- WordPress
- Drupal
- Joomla
  
  
[Web App Enumeration & Tools](8.3.1&2%20-%20Browser%20Dev%20Tools.md)  
  
[Admin Consoles](8.x%20-%20Admin%20Consoles.md)  
  
[Burp Suite](BurpSuite.md)  
  
[XSS](8.4%20-%20XSS.md)  
  
[Directory Traversal](9.1%20-%20Directory%20Traversal.md)  

[File Inclusion](9.2%20-%20File%20Inclusion.md)  

[SQL Injection](10.x%20-%20SQLi.md)  
  

Some things to consider when attempting to bypass login prompts:  
  
Like below, login forms can include tokens to prevent brute forcing and other attacks.  
  
We can also see that the form sets a _set_session_ parameter which is unique for each request.  
If we change the _set_session_ parameter or _token_ parameter and they don't match the values of the _phpMyAdmin_ cookie, the site will return an error:
![[login_token.png]]

We can use BurpSuite's Intruder to overcome this protective measure & ensure the values match.