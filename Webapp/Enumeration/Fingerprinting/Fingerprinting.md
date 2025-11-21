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

[[Nmap]] — Search for additional version information

```sh
nmap -sV [--version-all] <target> [--stats-every=10s] -oA http-version
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
nmap -sV <target> --script=http-enum [--stats-every=10s] -oA http-script-enum
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

<!-- }}} -->
