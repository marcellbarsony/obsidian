---
id: Findomain
tags:
  - Networking/Services/DNS/Tools/host
links: "[[Networking/Services/General]]"
---


# Findomain

[Findomain](https://github.com/Findomain/Findomain)
is the fastest and complete solution for domain recognition.

Supports screenshoting, port scan, HTTP check,
data import from other tools, subdomain monitoring,
alerts via Discord, Slack and Telegram,
multiple API Keys for sources and much more

Findomain uses Certificate Transparency logs
and well-tested APIs to find subdomains

___

<!-- Installation {{{-->
## Installation

Install on Debian-based distributions

```sh
sudo apt install findomain
```

Verify installation

```sh
findomain -h
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

DNS Subdomain enumeration

```sh
findomain -t "<target_domain>" -a
```

___
<!-- }}} -->
