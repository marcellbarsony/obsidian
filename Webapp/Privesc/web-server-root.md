# Web Server Root

Check the web server's root directory (`/var/www/`) for plain-text passwords

```sh
cat /var/www/* | grep -i passw*
```
