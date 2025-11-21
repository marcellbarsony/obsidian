---
id: Virtual Hosts
aliases: []
tags:
  - Webapp/Enumeration/Infrastructure/Virtual_Hosts
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
(*e.g., example.com*) or subdomains (*e.g., dev.example.com*).

> [!tip]
>
> If a **Virtual Host** doesn't have a DNS record, it can be accessed
> by modifying the [[DNS/General#Hosts File|hosts file]]

> [!todo]
>
> - [HTB Forums](https://forum.hackthebox.com/t/virtual-hosts-task-1st-question/323275)
> - [HTB Forums](https://forum.hackthebox.com/t/stuck-on-information-gathering-vhosts/316453/13)
> - [HTB Forums](https://forum.hackthebox.com/t/how-do-i-know-if-its-neccessary-to-change-etc-hosts-for-a-machine/243490/3)

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

<!-- Server VHost Lookup {{{-->
## Server VHost Lookup

A web server determines the correct content to serve
based on the `Host` header

> [!info]-
>
> ![[virtualhost_lookup.png]]

1. **Browser requests a website**:
   The browser initiates an HTTP request to the web server
   associated with the domain's IP address

2. **Host header reveals the domain**:
   The browser includes the domain name in the request's `Host` header,
   which acts as a label to inform the web server which website
   is being requested

3. **Web server determines the virtual host**:
   The web server receives the request, examines the `Host` header,
   and checks its virtual host configuration to find a matching entry
   for the requested domain name

4. **Serving the right content**:
   The web server retrieves the resources associated with the website
   and sends them back as the HTTP response

<!-- Brute Force {{{-->
### Brute Force

Virtual host fuzzing is recommended
to possibly find alternate domain names of subdomains
that point to a virtual host

> [!tip]- Wordlists
>
> [[SecLists]] — [Discovery/DNS](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS)
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
> and it could lead to an unintended denial of service

[[Gobuster]]

```sh
gobuster vhost -u http://<target> -w <wordlist.txt> -t 60 --append-domain
```
```sh
gobuster vhost -u http://<target> -w <wordlist.txt> -p pattern --exclude-length 301 -t 60
```
```sh
gobuster vhost --useragent "PENTEST" --wordlist "<wordlist.txt>" --url <target>
```

> [!info]-
>
> - `-t 60`: Number of threads
> - `-p pattern`: The `pattern` file contains the domain name
> - `--exclude-length 301`: Ignore results whose response body length
>    equals 301 bytes
>
> ```sh
> cat pattern
> ```
> ```sh
> {GOBUSTER}.inlanefreight.htb
> ```

[[Ffuf]]

```sh
ffuf -H "Host: FUZZ.<domain>" -H "User-Agent: PENTEST" -c -w "<wordlist.txt>" -u <target>
```
```sh
ffuf -c -r -w "<wordlist.txt>" -u "http://FUZZ.<target>/"
```

Filter results by response sizes (*e.g., `-fs 109, 208`*)

```sh
ffuf -w namelist.txt -u http://10.129.184.109 -H "HOST: FUZZ.inlanefreight.htb" -fs 10918
```

___
<!-- }}} -->

<!-- }}} -->

<!-- Hosts {{{-->
## Hosts

> [!tip]
>
> Add the discovered virtual hosts to `/etc/hosts`

```sh
sudoedit /etc/hosts
```

```sh
sudo sh -c "echo '10.129.122.20 app.inlanefreight.local dev.inlanefreight.local' >> /etc/hosts"
```
___
<!-- }}} -->

<!-- Enumeration {{{-->
## Enumeration

<!-- Banner Grabbing {{{-->
### Banner Grabbing

Show response headers

```sh
curl -I http://<target>
```

```sh
curl -s -D - -o /dev/null -H "Host: <target_vhost>" http://<target_ip>/
```

<!-- Info {{{-->
> [!info]-
>
> - `-s`: Silence progress/output
> - `-D -`: Dump response headers to `STDOUT`
> - `-o /dev/null`: Discard the body
> - `-H "Host: …"`: Set the Host header (*for vhost brute-forcing*)
<!-- }}} -->

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

<!-- }}} -->

<!-- Invalid Header {{{-->
### Invalid Header

Feed `localhost` header

```sh
curl -v -H "Host: localhost" http://<target_ip>/
```

Feed random host header

```sh
curl -v -H "Host: random" http://<target_ip>/
```

<!-- }}} -->

___
<!-- }}} -->
