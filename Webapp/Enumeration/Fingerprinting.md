---
id: Fingerprinting
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Fingerprinting

Fingerpring the web server for version, application framework, authentication
options, and missing security options.

## Type & Web Server Version

<!-- Nmap {{{-->
### Nmap Scan

```sh
nmap -sV [--version-all] <target_url>
```

> [!example]-
>
>```sh
>nmap -sV --version-all example.com
>```

#### Script Scan

Run the [http-enum script](https://nmap.org/nsedoc/scripts/http-enum.html)
to enumerate common web application directories

```sh
nmap -sV --script=http-enum -oA target_http_enum_scan <target_ip>
```

> [!info]-
>
> - `-sV`: Enable service/version detection
> - `--script=http-enum`: Run `http-enum` scripp
> - `-oA`: Save output in all fomats
<!-- }}} -->

### Banner Grabbing

<!-- cURL {{{-->
#### cURL

Banner grabbing with cURL

```sh
curl -I http://<target_url>
```

> [!example]-
>
>```sh
># Banner grabbing & Web server headers
>curl -IL http://example.com
>
># Spoof user agent and follow redirects
>curl -A "Custom user-agent" -L {target_ip}
>```
<!-- }}} -->

<!-- WhatWeb {{{-->
#### WhatWeb

- [GitHub - WhatWeb](https://github.com/urbanadventurer/WhatWeb)

Extract the version of the web server, supporting frameworks, applications, and
CMS with [WhatWeb](https://whatweb.net/)

Default scan

```sh
whatweb <target_ip>
```

Dismiss errors

```sh
whatweb --no-errors 10.10.10.0/24
```

Set aggression level to 3 (Scale: `1`-`4`, Default: `1`)

```sh
whatweb -a 3 <target_ip>
```
<!-- }}} -->

<!-- Netcat {{{-->
#### Netcat

Grab the banner with [netcat](https://nmap.org/ncat/)

```sh
nc <target_url> 80
```

Then type

```sh
HEAD / HTTP/1.0
Host: <target_url>
```
<!-- }}} -->

<!-- Error Page {{{-->
### Error Page

Retrieve the error page

```sh
curl -X GET http://example.com/404page
```
<!-- }}} -->

<!-- Nikto Vulnerability Scanner {{{-->
### Nikto Vulnerability Scanner

Scan the page with [Nikto](https://github.com/sullo/nikto)

```sh
nikto -h http://<target_url>
```

> [!example]-
>
>```sh
>nikto -h http://example.com
>```
<!-- }}} -->

## Version Details & CVEs

Search for additional version information

### Version Number

Identify the version number of the underlying web technologies

### Public Exploits

Search for well-known vulnerabilities and exploits

- Web
- Searchsploit
