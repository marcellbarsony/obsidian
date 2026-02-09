---
id: Enumeration
aliases: []
tags:
  - Networking/Services/HTTP/Enumeration
links: "[[Networking/Services/General]]"
---

# Enumeration

Enumerate the web service for version, application framework,
authentication options, and missing security options

___

<!-- Service {{{-->
## Service

[[Nmap]] — Default script scan

```sh
nmap -sC $target -p 80,443 -oA http-script-default
```

[[Nmap]] — Search for additional version information

```sh
nmap -sV [--version-all] $target [--stats-every=10s] -oA http-version
```
```sh
nmap -sV $target --version-all
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap -sV --version-all example.com
> ```
>
<!-- }}} -->

[[Nmap]] — Enumerate common web application directories
(*[http-enum script](https://nmap.org/nsedoc/scripts/http-enum.html)*)

```sh
nmap -sV $target --script=http-enum -oA http-script-enum
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
