---
id: Subdomain
aliases: []
tags:
  - Webapp/Enumeration/Infrastructure/Subdomain
---

# Subdomain

[[DNS/General#Subdomain|Subdomain]] enumeration

<!-- Hosts {{{-->
> [!tip] Hosts
>
> Add the discovered subdomains hosts to the
> [[DNS/General#Hosts File|Hosts File]]
>
> ```sh
> sudo sh -c "echo '$target sd1.target.com sd2.target.com' >> /etc/hosts"
> ```
>
<!-- }}} -->

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
> **Wordlists**
>
> Subdomains Top 1 Million
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
> Shubs
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> Bitquark
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> Combined
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
<!-- }}} -->

[[Gobuster]]

```sh
gobuster
```
