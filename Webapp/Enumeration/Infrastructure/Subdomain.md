---
id: Subdomain
aliases: []
tags:
  - Webapp/Enumeration/Infrastructure/Subdomain
---

# Subdomain

[[DNS/General#Subdomain|Subdomain]] enumeration

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

<!-- Info {{{-->
> [!info]-
>
> - `-c`: Colorize output (*default: `false`*)
> - `-r`: Follow redirects (*default: `false`*)
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/namelist.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> Wordlists - Additional
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> Wordlist - Combined
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
<!-- }}} -->
