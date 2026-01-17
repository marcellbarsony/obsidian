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
