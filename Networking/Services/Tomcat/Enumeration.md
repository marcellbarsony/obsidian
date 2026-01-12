---
id: Enumeration
aliases: []
tags:
  - Networking/Services/Tomcat/Enumeration
---

# Enumeration

___

<!-- Service {{{-->
## Service

Enumerate the Tomcat service

<!-- Detect {{{-->
### Detect

Detect Tomcat Service

```sh
nmap -p 8080,8443,8009 $target
```

<!-- }}} -->

<!-- Banner {{{-->
### Banner

Grab service banner and server header

[[Netcat]]

Connect and grab service banner

```sh
nc $target 8080
GET / HTTP/1.1
Host: $target
```

[[Curl]]

Grab service banner

```sh
curl -I http://$target:8080
```

Check server header

```sh
curl -s -D - http://$target:8080 | grep Server
```

[[Nmap]]


Server header detection

```sh
nmap $target -p 8080 --script http-server-header -oA tomcat-http-server-header
```

<!-- }}} -->

<!-- Version {{{-->
### Version

Common version disclosure locations

```sh
http://$target:8080/
```
```sh
curl -s http://$target:8080/docs/
```
```sh
curl -s http://$target:8080/docs/ | grep Tomcat
```
```sh
curl -s http://$target:8080/examples/
```
```sh
curl -s http://$target:8080/RELEASE-NOTES.txt
```
```sh
curl -s http://$target:8080/docs/RELEASE-NOTES.txt
```
```sh
curl -s http://$target:8080/manager/status
```

[[cURL]]

Check error pages for version

```sh
curl -i curl http://$target:8080/nonexistent
```

Check documentation pages

```sh
curl http://$target:8080/docs/
```

[[Nmap]]

Version detection

```sh
nmap $target -p 8080,8443 -sV -oA tomcat-version
```

<!-- }}} -->

<!-- Scripts {{{-->
### Scripts

[[Nmap]]

HTTP methods enumeration

```sh
nmap $target -p 8080 --script http-methods -oA tomcat-scripts-http-methods
```

Directory enumeration

```sh
nmap $target -p 8080 --script http-enum -oA tomcat-scripts-directories
```

Tomcat-specific scripts

```sh
nmap $target -p 8080 --script http-tomcat-* -oA tomcat-scripts-all
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Directories {{{-->
## Directories

Enumerate Tomcat directories

<!-- Tip {{{-->
> [!tip]- Wordlists
>
> ```sh
> /usr/share/wordlists/dirb/common.txt
> ```
> ```sh
> /usr/share/seclists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt
> ```
<!-- }}} -->

[[Gobuster]]

```sh
gobuster dir -u http://$target:8080 -w <wordlist.txt>
```

[dirb](https://www.kali.org/tools/dirb/)

```sh
dirb http://$target:8080 <wordlist.txt>
```

[[Ffuf]]

```sh
ffuf -u http://$target:8080/FUZZ -w <wordlist.txt>
```

___
<!-- }}} -->

<!-- Manager {{{-->
## Manager

Enumerate the exact locations of the
[[Exploitation#Web Application Manager|Web Applicaiton Manager]]
(*`/manager` and `/host-manager` directories*)
as their names might be altered

```sh
http://$target:8080/manager
```

```sh
http://$target:8080/%252E%252E/manager/html
```

```sh
http://$target:8080/host-manager
```

___
<!-- }}} -->

<!-- Password {{{-->
## Password

Accessing `/auth.jsp` may reveal the password in a backtrace

```sh
http://$target:8080/auth.jsp
```

___
<!-- }}} -->

<!-- Scripts {{{-->
## Scripts

Apache Tomcat versions `4.x` to `7.x` include example scripts
that are susceptible to information disclosure
and cross-site scripting (*XSS*) attacks

<!-- }}} -->

<!-- User {{{-->
## User

Enumerate Tomcat users and authentication mechanisms

Check `tomcat-users.xml` (*if accessible*)

```sh
curl http://$target:8080/tomcat-users.xml
```

```sh
curl http://$target:8080/conf/tomcat-users.xml
```

[[Metasploit]] — [Apache Tomcat User Enumeration](https://www.rapid7.com/db/modules/auxiliary/scanner/http/tomcat_enum/)

```sh
use auxiliary/scanner/http/tomcat_enum
```

<!-- Info {{{-->
> [!info]-
>
> This module enumerates Apache Tomcat's usernames
> via malformed requests to `j_security_check`,
> which can be found in the web administration package
>
> It should work against Tomcat servers `4.1.0` - `4.1.39`,
> `5.5.0` - `5.5.27`, and `6.0.0` - `6.0.18`
>
> Newer versions no longer have the "admin" package by default. The 'admin' package
> is no longer provided for Tomcat 6 and later versions
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> use auxiliary/scanner/http/tomcat_enum
> set RHOSTS target.com
> set RPORT 8080
> run
> ```
<!-- }}} -->

___
<!-- }}} -->
