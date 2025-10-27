---
id: Fingerprinting
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Fingerprinting

Fingerpring the web server for version, application framework, authentication
options, and missing security options

___

<!-- Type & Web Server Version {{{-->
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

<!-- Error Page {{{-->
### Error Page

Retrieve the error page

```sh
curl -X GET http://example.com/404page
```
<!-- }}} -->

___
<!-- }}} -->

<!-- Version Details & CVEs {{{-->
## Version Details & CVEs

Search for additional version information

### Version Number

Identify the version number of the underlying web technologies

### Public Exploits

Search for well-known vulnerabilities and exploits

- Web
- Searchsploit

___
<!-- }}} -->
