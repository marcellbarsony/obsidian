---
id: Fingerprinting
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting
links: "[[Webapp/Enumeration/General|General]]"
---

# Fingerprinting

Fingerpring the web server for version, application framework,
authentication options, and missing security options

<!-- Info {{{-->
> [!info]- Resources
>
> OWASP WSTG
>
> [Fingerprint Web server](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
>
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> Servers running older versions of software
> without up-to-date security patches
> can be susceptible to known version-specific exploits
>
<!-- }}} -->


___

<!-- Web Server {{{-->
## Web Server

[[HTTP/Enumeration|Enumerate]] the [[HTTP/General|HTTP service]]

[[Nmap]] — Search for additional version information

```sh
nmap -sV [--version-all] $target [--stats-every=10s] -oA http-version
```
```sh
nmap -sV $target --version-all -oA http-version
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap -sV --version-all example.com
> ```
<!-- }}} -->

[[Nmap]] — Enumerate common web application directories
(*[http-enum script](https://nmap.org/nsedoc/scripts/http-enum.html)*)

```sh
nmap -sV $target --script=http-enum [--stats-every=10s] -oA http-script-enum
```

<!-- Info {{{-->
> [!info]-
>
> - `-sV`: Enable service/version detection
> - `--script=http-enum`: Run `http-enum` scripp
> - `-oA`: Save output in all fomats
<!-- }}} -->

___
<!-- }}} -->
