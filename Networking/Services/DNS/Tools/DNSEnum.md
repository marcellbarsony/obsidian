---
id: DNSEnum
aliases: []
tags:
  - Networking/Services/DNS/Tools/DNSEnum
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# DNSEnum

[dnsenum](https://github.com/fwaeytens/dnsenum)
dnsenum is a perl script that enumerates DNS information

```sh
dnsenum --enum <target> -f <wordlist.txt> -r
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
> ```
> ```sh
> dnsenum VERSION:1.2.6
>
> -----   inlanefreight.com   -----
>
>
> Host's addresses:
> __________________
>
> inlanefreight.com.                       300      IN    A        134.209.24.248
>
> [...]
>
> Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:
> _______________________________________________________________________________________
>
> www.inlanefreight.com.                   300      IN    A        134.209.24.248
> support.inlanefreight.com.               300      IN    A        134.209.24.248
> [...]
>
>
> done.
> ```
<!-- }}} -->
