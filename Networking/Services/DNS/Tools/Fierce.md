---
id: Fierce
aliases: []
tags:
  - Networking/Services/DNS/Tools/Fierce
links: "[[Webapp/Enumeration/General|General]]"
---

# Fierce

[fierce](https://github.com/mschwager/fierce)
is a DNS reconnaissance tool for locating non-contiguous IP space

**fierce** automates zone transfers and performs dictionary attacks

<!-- Installation {{{-->
## Installation

[Kali Tools](https://www.kali.org/tools/fierce/)

```sh
sudo apt install fierce
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Automate zone transfer attack against a target domain

```sh
fierce --domain <target_domain> --dns-servers <dns_ip>
```

___
<!-- }}} -->
