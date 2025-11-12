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

<!-- Version Details & CVEs {{{-->
## Version Details & CVEs

Search for additional version information

<!-- Nmap {{{-->
### Nmap Scan

```sh
nmap -sV [--version-all] <target> [--stats-every=10s] -oA http-version-scan
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap -sV --version-all example.com
> ```
<!-- }}} -->

#### Script Scan

[http-enum script](https://nmap.org/nsedoc/scripts/http-enum.html) —
Enumerate common web application directories

```sh
nmap -sV <target> --script=http-enum [--stats-every=10s] -oA script-http-enum
```

<!-- Info {{{ -->
> [!info]-
>
> - `-sV`: Enable service/version detection
> - `--script=http-enum`: Run `http-enum` scripp
> - `-oA`: Save output in all fomats
<!-- }}} -->


<!-- }}} -->

<!-- Public Exploits {{{-->
### Public Exploits

Search for well-known vulnerabilities and exploits

- Web
  (*e.g., [Exploit DB](https://www.exploit-db.com/),
  [CVE Details](https://www.cvedetails.com/),
  [NVD NIST](https://nvd.nist.gov/vuln/search#/nvd/home?resultType=records),
  [MITRE](https://www.cve.org/)*)
- [[SearchSploit]]

<!-- }}} -->

___
<!-- }}} -->
