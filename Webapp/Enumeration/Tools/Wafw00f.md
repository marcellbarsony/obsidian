---
id: Wafw00f
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Wafw00f
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Wafw00f

[Wafw00f](https://github.com/EnableSecurity/wafw00f) allows to identify and
fingerprint Web Application Firewall products protecting a website

___

<!-- Install {{{-->
## Install

Install **Wafw00f** with [pip](https://pypi.org/project/pip/)

```sh
python3 -m pip install wafw00f
```

```sh
pip3 install wafw00f
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Run **Wafw00f** against a target website

```sh
wafw00f <target>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> wafw00f inlanefreight.com
> ```
> ```sh
>                 ______
>                /      \
>               (  W00f! )
>                \  ____/
>                ,,    __            404 Hack Not Found
>            |`-.__   / /                      __     __
>            /"  _/  /_/                       \ \   / /
>           *===*    /                          \ \_/ /  405 Not Allowed
>          /     )__//                           \   /
>     /|  /     /---`                        403 Forbidden
>     \\/`   \ |                                 / _ \
>     `\    /_\\_              502 Bad Gateway  / / \ \  500 Internal Error
>       `_____``-`                             /_/   \_\
>
>                         ~ WAFW00F : v2.2.0 ~
>         The Web Application Firewall Fingerprinting Toolkit
>
> [*] Checking https://inlanefreight.com
> [+] The site https://inlanefreight.com is behind Wordfence (Defiant) WAF.
> [~] Number of requests: 2
> ```
> - The website is protected by the Wordfence Web Application Firewall (WAF),
> developed by Defiant
<!-- }}} -->

___
<!-- }}} -->
