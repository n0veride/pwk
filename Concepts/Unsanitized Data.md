
Unsanitized data allows an attacker to inject and, possibly, execute code creating a [XSS](8.4%20-%20XSS.md) vulnerability.  

Data/ Input Sanitization happens when a user's website data input is processed, removing or transforming all dangerous characters or strings.  


Parameterized queries (aka Prepared Statements) can help mitigate [SQL Injection](9.4.5%20SQLi.md)  
Puts placeholders into the statements.  
User input is supplied alongside the statement and the db binds the values to the statement.  
Creates a layer of separation btw the statement code and the data values  


Ex non-parameterized:  
```bash
$name = $_REQUEST['name'];  
$email = $_REQUEST['email'];  
$sql = "INSERT INTO CustomerTable (Name, Email) VALUES ('$name', '$email')"
```

Ex parameterized:  
```bash
$name = $_REQUEST['name'];  
$email = $_REQUEST['email'];  
$params = array($name, $email);  
$sql = "INSERT INTO CustomerTable (Name, Email) VALUES (?,?)";  
  
$stmt = sqlsrv_query($conn, $tsql, $params);
```
	sqlsrv_query - Function that returns a PHP statement resource  
	$conn - Open connection  
	$sql - SQL query  
	$params - Parameter array