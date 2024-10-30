
Setting up servers on port 7331:  
• Will host any files or directories from current working path.  

Python:
```python
python -m SimpleHTTPServer 7331
```  
  
Python3:  
```python
python3 -m http.server 7331
```

PHP:  
```php
php -S 0.0.0.0:7331
```

Ruby:  
```ruby
ruby -run -e httpd . -p 7331
```

Busybox:  
```bash
busybox httpd -f -p 7331
```


## Web root directories

##### Apache
- /var/www/html/  
##### MariaDB
- C:/xampp/htdocs/  
##### Nginx
- /usr/share/nginx/html  
- /data/www/

##### IIS Servers
- c:\inetpub\wwwroot\