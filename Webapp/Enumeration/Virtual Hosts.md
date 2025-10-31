---
id: Virtual Hosts
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Virtual_Hosts
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Virtual Hosts

[Virtual Hosting](https://en.wikipedia.org/wiki/Virtual_hosting)
is the ability of web servers to distinguish between multiple websites
or applications sharing the same IP address by leveraging
the `HTTP Host` header.

**Virtual Hosts** are configurations within a web server
that allow multiple websites or applications
to be hosted on a single server.

**Virtual Hosts** can be associated with top-level domains
(*e.g., example.com*) or subdomains (*e.g., dev.exmaple.com*).

> [!tip]-
>
> If a **Virtual Host** doesn't have a DNS record, it can be accessed
> by modifying the [[DNS/General#Hosts File|hosts file]]

___

<!-- Configuration {{{-->
## Configuration

Virtual hosts can also be configured to use different domains,
not just subdomains

<!-- Example {{{-->
> [!example]-
>
> Example of name-based virtual host configuration in Apache
>
> ```html
> <VirtualHost *:80>
>     ServerName www.example1.com
>     DocumentRoot /var/www/example1
> </VirtualHost>
>
> <VirtualHost *:80>
>     ServerName www.example2.org
>     DocumentRoot /var/www/example2
> </VirtualHost>
>
> <VirtualHost *:80>
>     ServerName www.another-example.net
>     DocumentRoot /var/www/another-example
> </VirtualHost>
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Discovery {{{-->
## Discovery

Virtual Host discovery with [[Gobuster#Brute Forcing|Gobuster]]

```sh
gobuster vhost -u http://<target> -w <wordlist.txt> --append-domain
```

> [!tip]- Wordlists
>
> [SecLists/Discovery/DNS](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS)
>
> ```sh
> /usr/share/seclists/Discovery/DNS/namelist.txt
> ```
> ```sh
> /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
> ```

> [!warning]
>
> Virtual Host Discovery can generate significant traffic
> and might be detected by intrusion detection systems (*IDS*)
> or web application firewalls (*WAF*)

___
<!-- }}} -->

<!-- Enumeration {{{-->
## Enumeration

### Banner Grabbing

Show response headers

```sh
curl -s -D - -o /dev/null -H "Host: <target_vhost>" http://<target_ip>/
```

> [!example]-
>
> ```sh
> curl -s -D - -o /dev/null -H "Host: app.inlanefreight.local" http://10.129.222.107/
> ```

Show response headers and body

```sh
curl -v -H "Host: <target_vhost>" http://<target_ip>/
```

> [!example]-
>
> ```sh
> curl -v -H "Host: app.inlanefreight.local" http://10.129.222.107/
> ```

Raw TCP

```sh
printf 'GET / HTTP/1.1\r\nHost: app.inlanefreight.local\r\nConnection: close\r\n\r\n' | nc 10.129.222.107 80
```

> [!tip]
>
> Feed `localhost` header
>
> ```sh
> curl -v -H "Host: localhost" http://<target_ip>/
> ```
>
> Feed random host header
>
> ```sh
> curl -v -H "Host: random" http://<target_ip>/
> ```
___
<!-- }}} -->
