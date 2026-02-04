---
id: Virtual Hosts
aliases: []
tags:
  - Webapp/Enumeration/Infrastructure/Virtual_Hosts
links: "[[Webapp/Enumeration/General|General]]"
---

# Virtual Hosts

[Virtual Hosting](https://en.wikipedia.org/wiki/Virtual_hosting)
(*or [Server Blocks](https://docs.nginx.com/)*)
is the ability of web servers to distinguish between multiple websites
or applications sharing the same IP address by leveraging
the `HTTP Host` header

**Virtual Hosts** are configurations within a web server
that allow multiple websites or applications
to be hosted on a single server

**Virtual Hosts** can be associated with top-level domains
(*e.g., example.com*) or subdomains (*e.g., dev.example.com*)

<!-- Hosts File {{{-->
> [!tip] Hosts File
>
> If a **Virtual Host** doesn't have a DNS record,
> it can be accessed by modifying the
> [[DNS/General#Hosts File|Hosts File]]
<!-- }}} -->

___

<!-- General {{{-->
## General

<!-- Configuration {{{-->
### Configuration

Virtual hosts can also be configured to use different domains,
not only subdomains

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

<!-- }}} -->

<!-- Server VHost Lookup {{{-->
### Server VHost Lookup

A web server determines the correct content to serve
based on the `Host` header

<!-- Info {{{-->
> [!info]-
>
> ![[virtualhost_lookup.png]]
<!-- }}} -->

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

<!-- }}} -->

___
<!-- }}} -->

<!-- Discovery {{{-->
## Discovery

<!-- Fuzzing {{{-->
### Fuzzing

Virtual Host fuzzing is recommended
to possibly find alternate domain names of subdomains
that point to a virtual host

<!-- Warning {{{-->
> [!warning]
>
> Virtual Host Discovery can generate significant traffic
> and might be detected by intrusion detection systems (*IDS*)
> or web application firewalls (*WAF*)
> and it could lead to an unintended denial of service
<!-- }}} -->

<!-- Hosts {{{-->
> [!tip] Hosts
>
> Add the discovered virtual hosts to the
> [[DNS/General#Hosts File|Hosts File]]
>
> ```sh
> sudo sh -c "echo '$target sd1.target.com sd2.target.com' >> /etc/hosts"
> ```
<!-- }}} -->

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> - [[SecLists#Subdomains|SecLists]]
>
<!-- }}} -->

[[Ffuf]]

```sh
ffuf -w <wordlist> -u http://FUZZ.$target/ -c -r
```

```sh
ffuf -w <wordlist> -u http://$target/ -H "Host: FUZZ.<domain>" -c -r
```

```sh
ffuf -w <wordlist> -u http://$target/ -H "Host: FUZZ.<domain>" -H "User-Agent: PENTEST" -c -r
```

<!-- Info {{{-->
> [!info]-
>
> - `-c`: Colorize output (*default: `false`*)
> - `-r`: Follow redirects (*default: `false`*)
> - `-u`: Target URL
> - `-w`: Wordlist file path and (*optional*) keyword
>         separated by colon.
>         (*e.g., `'/path/to/wordlist:KEYWORD'`*)
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Fuzz URL
>
> ```sh
> ffuf -w <wordlist> -u http://FUZZ.$target/
> ```
>
> <!-- Example {{{-->
> > [!example]-
> >
> > **Wordlists**
> >
> > Subdomains Top 1 Million (*VHosts*)
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
> > -u http://FUZZ.$target/ \
> > -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ \
> > -u http://FUZZ.$target/ \
> > -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ \
> > -u http://FUZZ.$target/ \
> > -ic
> > ```
> >
> > DNS Namelist
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/namelist.txt:FUZZ \
> > -u http://FUZZ.$target/ \
> > -ic
> > ```
> >
> > Shubs
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt:FUZZ \
> > -u http://FUZZ.$target/ \
> > -ic
> > ```
> >
> > Bitquark
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ \
> > -u http://FUZZ.$target/ \
> > -ic
> > ```
> >
> > Combined List
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt:FUZZ \
> > -u http://FUZZ.$target/ \
> > -ic
> > ```
> >
> > <!-- Info {{{-->
> > > [!info]-
> > >
> > > - bitquark-subdomains-top100000.txt
> > > - shubs-subdomains.txt
> > > - subdomains-top1million-110000.txt
> > <!-- }}} -->
> >
> <!-- }}} -->
>
> Fuzz Host header
>
> ```sh
> ffuf -w <wordlist> -u http://$target/ -H "Host: FUZZ.<domain>" -c -r
> ```
>
> <!-- Example {{{-->
> > [!example]-
> >
> > **Wordlists**
> >
> > Subdomains Top 1 Million (*VHosts*)
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
> > -u http://$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ \
> > -u http://$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ \
> > -u http://$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -ic
> > ```
> >
> > Namelist
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/namelist.txt:FUZZ \
> > -u http://$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -ic
> > ```
> >
> > Shubs
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt:FUZZ \
> > -u http://$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -ic
> > ```
> >
> > Bitquark
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ \
> > -u http://$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -ic
> > ```
> >
> > Combined List
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt:FUZZ \
> > -u http://$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -ic
> > ```
> >
> > <!-- Info {{{-->
> > > [!info]-
> > >
> > > - bitquark-subdomains-top100000.txt
> > > - shubs-subdomains.txt
> > > - subdomains-top1million-110000.txt
> > <!-- }}} -->
> >
> <!-- }}} -->
>
<!-- }}} -->

[[Gobuster]]

```sh
gobuster vhost -u http://$target -w <wordlist>
```
```sh
gobuster vhost -u http://$target -w <wordlist> [--domain <domain>] --append-domain -t 60
```
```sh
gobuster vhost -u http://$target -w <wordlist> -p <pattern_file> --exclude-length 301
```
```sh
gobuster vhost --useragent "PENTEST" --wordlist "<wordlist>" --url $target
```

<!-- Info {{{-->
> [!info]-
>
> - `-p pattern`: The `pattern` file contains the domain name
>
> ```sh
> cat pattern
> ```
> ```sh
> {GOBUSTER}.inlanefreight.htb
> ```
>
> - `-t 60`: Number of threads
> - `-u`: Set URL to machine IP
> - `-w`: Wordlist
> - `--append-domain`: Appends the configured domain to each entry in the wordlist
> - `--exclude-length 301`: Ignore results whose response body length
>    equals 301 bytes
> - `--useragent`: Define custom [[User Agent]]
>
<!-- }}} -->

<!-- Domain {{{-->
> [!tip]- Domain
>
> Defining a domain may be necessary
> when appending a domain (`--append-domain`)
>
> - `--domain <target.com>`: Set top- and second-level domains
>   in the `Hostname:` header
>
> - `-p <pattern_file>`: Set custom domain pattern in the pattern file
>
> ```sh
> cat pattern
> ```
> ```sh
> {GOBUSTER}.inlanefreight.htb
> ```
>
> <!-- VHost Header {{{-->
> > [!example]- VHost Header
> >
> > ```sh
> > HOST: admin.inlanefreight.thm
> > HOST: test.inlanefreight.thm
> > HOST: dev.inlanefreight.thm
> > ```
> <!-- }}} -->
>
<!-- }}} -->

<!-- }}} -->

<!-- Recursive Fuzzing {{{-->
### Recursive Fuzzing

Conduct recursive virtual host fuzzing on the virtual hosts found

<!-- Hosts {{{-->
> [!tip] Hosts
>
> Add the found virtual hosts to `/etc/hosts`
>
> ```sh
> sudo sh -c "echo '$target sd1.target.com sd1.target.com' >> /etc/hosts"
> ```
<!-- }}} -->

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> [[SecLists#Subdomains|SecLists]]
>
<!-- }}} -->

[[Ffuf]]

```sh
ffuf -w <wordlist> \
-u http://FUZZ.<vhost>.$target/ \
-c -r -ic
```

```sh
ffuf -w <wordlist> \
-u http://<vhost>.$target/ \
-H "Host: FUZZ.<domain>" \
-c -r -ic
```

```sh
ffuf -w <wordlist> \
-u http://<vhost>.$target/ \
-H "Host: FUZZ.<domain>" \
-H "User-Agent: PENTEST" \
-c -r -ic
```

<!-- Info {{{-->
> [!info]-
>
> - `-c`: Colorize output (*default: `false`*)
> - `-r`: Follow redirects (*default: `false`*)
> - `-ic`: Ignore comment in wordlist
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Fuzz URL Recursively
>
> ```sh
> ffuf -w <wordlist> \
> -u http://FUZZ.<vhost>.$target/ \
> -c -r -ic
> ```
>
> <!-- Example {{{-->
> > [!example]-
> >
> > **Wordlists**
> >
> > Subdomains Top 1 Million (*VHosts*)
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
> > -u http://FUZZ.<vhost>.$target/ \
> > -c -r -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ \
> > -u http://FUZZ.<vhost>.$target/ \
> > -c -r -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ \
> > -u http://FUZZ.<vhost>.$target/ \
> > -c -r -ic
> > ```
> >
> > DNS Namelist
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/namelist.txt:FUZZ \
> > -u http://FUZZ.<vhost>.$target/ \
> > -c -r -ic
> > ```
> >
> > Shubs
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt:FUZZ \
> > -u http://FUZZ.<vhost>.$target/ \
> > -c -r -ic
> > ```
> >
> > Bitquark
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ \
> > -u http://FUZZ.<vhost>.$target/ \
> > -c -r -ic
> > ```
> >
> > Combined List
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt:FUZZ \
> > -u http://FUZZ.<vhost>.$target/ \
> > -c -r -ic
> > ```
> >
> > <!-- Info {{{-->
> > > [!info]-
> > >
> > > - bitquark-subdomains-top100000.txt
> > > - shubs-subdomains.txt
> > > - subdomains-top1million-110000.txt
> > <!-- }}} -->
> >
> <!-- }}} -->
>
> Fuzz Host header
>
> ```sh
> ffuf -w <wordlist> \
> -u http://<vhost>.$target/ \
> -H "Host: FUZZ.<domain>" \
> -c -r -ic
> ```
>
> <!-- Example {{{-->
> > [!example]-
> >
> > **Wordlists**
> >
> > Subdomains Top 1 Million (*VHosts*)
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -c -r -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -c -r -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -c -r -ic
> > ```
> >
> > Namelist
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/namelist.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -c -r -ic
> > ```
> >
> > Shubs
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -c -r -ic
> > ```
> >
> > Bitquark
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -c -r -ic
> > ```
> >
> > Combined List
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -c -r -ic
> > ```
> >
> > <!-- Info {{{-->
> > > [!info]-
> > >
> > > - bitquark-subdomains-top100000.txt
> > > - shubs-subdomains.txt
> > > - subdomains-top1million-110000.txt
> > <!-- }}} -->
> >
> <!-- }}} -->
>
> Fuzz Host header with custom User-Agent
>
> ```sh
> ffuf -w <wordlist> \
> -u http://<vhost>.$target/ \
> -H "Host: FUZZ.<domain>" \
> -H "User-Agent: PENTEST" \
> -c -r -ic
> ```
>
> <!-- Example {{{-->
> > [!example]-
> >
> > **Wordlists**
> >
> > Subdomains Top 1 Million (*VHosts*)
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -H "User-Agent: PENTEST" \
> > -c -r -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -H "User-Agent: PENTEST" \
> > -c -r -ic
> > ```
> >
> > ```sh
> > ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -H "User-Agent: PENTEST" \
> > -c -r -ic
> > ```
> >
> > Namelist
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/namelist.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -H "User-Agent: PENTEST" \
> > -c -r -ic
> > ```
> >
> > Shubs
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -H "User-Agent: PENTEST" \
> > -c -r -ic
> > ```
> >
> > Bitquark
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -H "User-Agent: PENTEST" \
> > -c -r -ic
> > ```
> >
> > Combined List
> >
> > ```sh
> > ffuf -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt:FUZZ \
> > -u http://<vhost>.$target/ \
> > -H "Host: FUZZ.<domain>" \
> > -H "User-Agent: PENTEST" \
> > -c -r -ic
> > ```
> >
> > <!-- Info {{{-->
> > > [!info]-
> > >
> > > - bitquark-subdomains-top100000.txt
> > > - shubs-subdomains.txt
> > > - subdomains-top1million-110000.txt
> > <!-- }}} -->
> >
> <!-- }}} -->
>
<!-- }}} -->

[[Gobuster]]

```sh
gobuster vhost -u http://<vhost>.$target -w <wordlist>
```
```sh
gobuster vhost -u http://<vhost>.$target -w <wordlist> [--domain <domain>] --append-domain -t 60
```
```sh
gobuster vhost -u http://<vhost>.$target.<tld> -w <wordlist> -p <pattern_file> --exclude-length 301
```
```sh
gobuster vhost --useragent "PENTEST" --wordlist "<wordlist>" --url <vhost>.$target
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> gobuster vhost -u http://web1337.inlanefreight.htb:42427 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 60
> ```
<!-- }}} -->

<!-- Info {{{-->
> [!info]-
>
> - `-p pattern`: The `pattern` file contains the domain name
>
> ```sh
> cat pattern
> ```
> ```sh
> {GOBUSTER}.inlanefreight.htb
> ```
>
> - `-t 60`: Number of threads
> - `-u`: Set URL to machine IP
> - `-w`: Wordlist
> - `--append-domain`: Appends the configured domain to each entry in the wordlist
> - `--exclude-length 301`: Ignore results whose response body length
>    equals 301 bytes
> - `--useragent`: Define custom [[User Agent]]
<!-- }}} -->

<!-- Domain {{{-->
> [!tip]- Domain
>
> Defining a domain may be necessary
> when appending a domain (`--append-domain`)
>
> - `--domain <target.com>`: Set top- and second-level domains
>   in the `Hostname:` header
>
> - `-p <pattern_file>`: Set custom domain pattern in the pattern file
>
> ```sh
> cat pattern
> ```
> ```sh
> {GOBUSTER}.inlanefreight.htb
> ```
>
> <!-- VHost Header {{{-->
> > [!example]- VHost Header
> >
> > ```sh
> > HOST: admin.inlanefreight.thm
> > HOST: test.inlanefreight.thm
> > HOST: dev.inlanefreight.thm
> > ```
> <!-- }}} -->
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Hosts {{{-->
## Hosts

<!-- Tip {{{-->
> [!tip]
>
> Add the discovered virtual hosts to `/etc/hosts`
<!-- }}} -->

```sh
sudoedit /etc/hosts
```

```sh
sudo sh -c "echo '$target sd1.target.com sd2.target.com' >> /etc/hosts"
```

<!-- Info {{{-->
> [!info]-
>
> - `-c`: Read commands from string.
>   If there are arguments after the string,
>   they are assigned to the positional parameters,
>   starting with `$0`
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo sh -c "echo '10.10.10.123   sd1.target.com sd2.target.com' >> /etc/hosts"
> ```
> ```sh
> 127.0.0.1        localhost
> ::1              localhost
> 127.0.1.1        arch
> 10.10.10.123     sd1.target.com sd2.target.com
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Enumeration {{{-->
## Enumeration

<!-- Banner Grabbing {{{-->
### Banner Grabbing

[[cURL]] - Show response headers

```sh
curl -I http://$target
```

```sh
curl -s -D - -o /dev/null -H "Host: <vhost>" http://$target/
```

<!-- Info {{{-->
> [!info]-
>
> - `-s`: Silence progress/output
> - `-D -`: Dump response headers to `STDOUT`
> - `-o /dev/null`: Discard the body
> - `-H "Host: …"`: Set the Host header (*for vhost brute-forcing*)
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> curl -s -D - -o /dev/null -H "Host: sd1.target.com" http://10.129.222.107/
> ```
<!-- }}} -->

[[cURL]] - Show response headers and body

```sh
curl -v -H "Host: <vhost>" http://$target/
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> curl -v -H "Host: sd1.target.com" http://10.129.222.107/
> ```
<!-- }}} -->

Raw TCP

```sh
printf 'GET / HTTP/1.1\r\nHost: <vhost>.<domain>.<tld>\r\nConnection: close\r\n\r\n' | nc $target 80
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> printf 'GET / HTTP/1.1\r\nHost: sd1.target.com\r\nConnection: close\r\n\r\n' | nc 10.129.222.107 80
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- Invalid Header {{{-->
### Invalid Header

[[cURL]] - Feed `localhost` header

```sh
curl -v -H "Host: localhost" http://$target/
```

[[cURL]] - Feed random host header

```sh
curl -v -H "Host: random" http://$target/
```

<!-- }}} -->

___
<!-- }}} -->
