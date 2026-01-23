---
id: Enumeration
aliases:
tags:
  - Networking/Services/HTTP/Microsoft-IIS/Enumeration
links: "[[Services]]"
---

# Enumeration

Enumerate Microsoft IIS service

___

<!-- Service {{{-->
## Service

[[Nmap]] — Default script scan

```sh
nmap -sC $target -p 80,443 -oA http-script-default
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> PORT   STATE SERVICE VERSION
> 80/tcp open  http    Microsoft IIS httpd 6.0
> | http-ntlm-info: 
> |   Target_Name: GRANPA
> |   NetBIOS_Domain_Name: GRANPA
> |   NetBIOS_Computer_Name: GRANPA
> |   DNS_Domain_Name: granpa
> |   DNS_Computer_Name: granpa
> |_  Product_Version: 5.2.3790
> |_http-server-header: Microsoft-IIS/6.0
> | http-methods: 
> |_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
> | http-webdav-scan: 
> |   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
> |   Server Type: Microsoft-IIS/6.0
> |   WebDAV type: Unknown
> |   Server Date: Wed, 21 Jan 2026 23:47:00 GMT
> |_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
> |_http-title: Under Construction
> Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
> ```
>
> The target is running a vulnerable version of Microsoft IIS
>
> ```sh
> 80/tcp open  http    Microsoft IIS httpd 6.0
> ```
>
<!-- }}} -->

___
<!-- }}} -->
