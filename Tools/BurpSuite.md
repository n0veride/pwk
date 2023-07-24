
289-298 - _Recersive Grep_  
  
  
GUI-Based collection of tools geared towards web app testing & a powerful proxy tool.  
  
Commercial versions include additional features, including a web app vuln scanner.  
  
  
Browsing to an HTTPS site while proxying traffic will present an “invalid certificate” warning.  
Burp can generate its own SSL/TLS cert (essentially MITM) and importing it into Firefox in order to capture traffic.  
  
_Proxy_ > _Options_ > _Proxy Listeners_ > _Regenerate CA certificate_  
  
Browse to [http://burp](http://burp) to find a link to the certificate and save the _cacert.der_ file  
Drag ‘n’ drop to Firefox and select _Trust this CA to identify websites_  
  

### Proxy tool:
Can intercept any request sent from the browser before it is passed onto the server.  
  
Can change the fields w/in the request such as parameter names, form values, adding new headers, etc.  
- Allows us to test how an app handles unexpected arbitrary input.  
Ex - Modify a request to submit 30 chars w/in an input field w/ a size limit of 20 chars.  
  
Disable _Intercept_:  
When _Intercept_ is enabled, we have to manually click on _Forward_ to send each request towards its destination or click _Drop_ to not send the request.  
(Can disable _Intercept_ at start up w/in _User Options_ > _Misc_ > _Proxy Interception_)  
  
_Options_ tab will help set the proxy listener settings. Default listener is localhost:8080  
  
_HTTP history_ will show once traffic has been sent through [BurpSuite](PWK--Tools--BurpSuite.html)  
  
262 - 271 \[\[\[ FoxyProxy Basic/ Standard \]\]\] ----- “Simple on/ off proxy switcher” add-on for Firefox
  
  
### Repeater tool:
Used to modify requests, resend them, and review the responses.  
  
Rt-click on a host w/in _Proxy_ > _HTTP history_, _Send to Repeater_  
  
Can edit the request and _Send_ to server. Able to display the raw server response on the right side of the window (good for enumerating db w/ [SQL ORDER BY](9.4.5%20SQLi.md))  
  
  
### Intruder tool:
Allows automation basic username and password combinations for web logins  
  
- Attempt login on site  
-  Find POST method for attempt under _Proxy_ > _HTTP history_  
- Rt-click > _Send to Intruder_  
- Payload markers (**§**) will surround available payload positions  
- _Clear_ and _Add_ markers to positions you want to attack  
- After payloads are selected > _Start Attack_  
- New results window will open  
- Check response codes and verify  
  
  
_**Target**_ **subtab:**  
	Info is prepopulated based on the request  
  
  
_**Positions**_ **subtab:**  
	Used to mark which fields we want to inject payloads into when an attack is run.  
		Cookie values and POST body values are marked as payload positions using a section sign (**§**) as the delimiter  
  
  
_**Payloads**_ **subtab:**  
	Used to set payloads via sets and wordlists.  
		Each set value matches the positions sequentially  
		Verify which Payload Set and which Payload Type to work with....  
  
*Note: The “token value” can often contain special characters, so it's important to deselect the option to URL-encode them  
  
  
_**Resource Pool**_ **subtab:**  
	Used to set up threading.  
		If _Recursive Grep_ errors w/ "payloads cannot be used with multiple request threads", create new Resourse Pool with 1 thread max.  
  
  
_**Options**_ **subtab:**  
	With a _Recursive Grep_ payload, we can set up options to extract values from a response and inject them into the next request:  
		- Add a _Grep - Extract_  
		- Highlight value needing extraction - If muoltiple instances of a value are set (ie: cookies), burp will always use the first instance it finds.  
		- _Set Payloads_ > _Payload Sets_ to _Recursive Grep_. _Payloads_ > _Payload Options_ will fill in with the values set in _Grep - Extract_ section  
  
  
  
  
  
**Attack Types:**  
- Sniper  
	- Uses a single set of payloads.  
	- Targets each payload position in turn and places each payload into that position in turn.  
	- Useful for fuzzing a number of request parameters individually for common vulns  
	- Number of requests generated is the product of the number of positions and the number of payloads in the payload set  
- Battering Ram  
	- Uses a single set of payloads.  
	- Iterates through the payloads and places the same payload into all of the defined payload positions at once.  
	- Useful where an attack requires the same input to be inserted in mulitple places w/in the request (ex: username w/in a cookie and body parameter)  
	- Number of requests generated is the number of payloads in the payload set.  
- Pitchfork  
	- Uses multiple sets of payloads.  
	- Allows setting a unique payload set for each position.  
	- First request places first payload from payload1 into position 1 & first payload from payload2 into position 2. Second request moves to 2nd payload from each set into respective positions.  
	- Useful where attack requires different but related input to be inserted in multiple places w/in the request (ex: username in one paramter, known ID corresponding to that username into another)  
	- Number of requests generated isthe number of payloads in the smallest payload set.  
- Cluster Bomb  
	- Uses multiple sets of payloads.  
	- Allows setting a unique payload set for each position.  
	- Iterates through each payload set in turn so that all permutations of payload combinations are tested.  
		- If there are 2 positions, the attack will place the 2st payload from payload2 into position 2 and iterated through all the payloads in payload1 in position 1.  
	- Useful where attack requires different and unrelated or unknown input to be inserted in multiple places (ex: guessing creds w/ a username in one position and a password in another)  
	- Number of requests generated is the product of the number of payloads in all defined payload sets - can be extremely large.