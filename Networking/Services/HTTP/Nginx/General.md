---
id: General
aliases: []
tags:
  - Networking/Services/HTTP/Nginx/General
links: "[[Services]]"
---

# General

[Nginx](https://nginx.org/) (*Engine X*)
is an HTTP web server, reverse proxy, content cache,
load balancer, TCP/UDP proxy server, and mail proxy server

___

<!-- Configuration {{{-->
## Configuration

2. Create a configuration file

```sh
vim /etc/nginx/sites-available/upload.conf
```

<!-- Example {{{-->
> [!example]-
>
>
> ```cfg
> server {
>     listen 9001;
>
>     location /SecretUploadDirectory/ {
>         root    /var/www/uploads;
>         dav_methods PUT;
>     }
> }
> ```
<!-- }}} -->


___
<!-- }}} -->
