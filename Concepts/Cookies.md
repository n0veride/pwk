
Used by websites to track _state_ and info about users: session management, tracking, personalization, etc.  
  
_**Cookie Editor**_ is a Firefox add-on that can easily set and manipulate cookies.  
  
  
  
  
[Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies) can be set with several optional flags:  
  
_**Secure:**_ Instructs the browser to only send cookies over encrypted connections preventing cleartext  
  
  
  
_**HTTPOnly:**_ Instructs the browser to allow JavaScript access to the cookie. If not set, can be stolen through [XSS](XSS.md) vuln & assuming other browser controls aren't in place/ can be bypassed.  
  
  
  
Broswer security dictates the scope of a cookie be defined: what URLs the cookies should be sent to:  
  
_**Domain:**_ Used to specify which hosts can receive a cookie  
If specified, all subdomains are included.  
If unspecified, attribute defaults to the same host _excluding_ subdomains  
  
_**Path:**_ Used to specify a URL path that must exist in the requested URL in order to send the Cookie header  
_%x2f_ ("/") is considered a directory separator allowing subdirectories to match as well.  
Ex: PATH=/docs  
/docs  
/docs/  
/docs/Web/  
/docs/Web/Http  
  
  
  
_**SameSite:**_ Lets servers specify whether/when cookies are sent with cross-site requests. http & https are considered different schemes. Helps mitigate CSRF  
3 possible values:  
**Strict**: Cookies are only sent to the site where it originated.  
**Lax**: Cookies are sent when the user navigates to the cookie's origin site. For example, by following a link from an external site. Default  
**None**: Cookies are sent on both originating and cross-site requests, but Secure attribute must be set