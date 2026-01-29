---
id: Usage
aliases: []
tags:
  - Networking/Services/HTTP/Nginx/Usage
links: "[[Services]]"
---

# Usage

___

<!-- Enabling PUT {{{-->
## Enabling PUT

1. Create a directory to handle uploaded files

```sh
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```

2. Change the owner to `www-data`

```sh
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

3. Create [[Nginx/General#Configuration|Nginx Configuration]] file

4. Symlink the site to the sites-enabled directory

```sh
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

5. Start Nginx

```sh
sudo systemctl restart nginx.service
```

6. Verify errors

```sh
tail -2 /var/log/nginx/error.log
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> 2020/11/17 16:11:56 [emerg] 5679#5679: bind() to 0.0.0.0:`80` failed (98: A`ddress already in use`)
> 2020/11/17 16:11:56 [emerg] 5679#5679: still could not bind()
> ```
<!-- }}} -->

```sh
ss -lnpt | grep 80
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> LISTEN 0      100          0.0.0.0:80        0.0.0.0:*    users:(("python",pid=`2811`,fd=3),("python",pid=2070,fd=3),("python",pid=1968,fd=3),("python",pid=1856,fd=3))
> ```
>
<!-- }}} -->

```sh
ps -ef | grep 2811
```

<!-- Example {{{-->
> [!example]-
>
> There is a a module listening on port 80
>
> ```sh
> user65      2811    1856  0 16:05 ?        00:00:04 `python -m websockify 80 localhost:5901 -D`
> root        6720    2226  0 16:14 pts/0    00:00:00 grep --color=auto 2811
> ```
>
<!-- }}} -->

7. Remove Nginx default configuration (*optional*)

```sh
sudo rm /etc/nginx/sites-enabled/default
```

### Upload File

[[cURL]]

```sh
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
> ```
>
<!-- }}} -->


___
<!-- }}} -->
