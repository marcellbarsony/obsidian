---
id: Amass
aliases: []
tags:
  - Networking/Tools/Amass
links: "[[Networking/Tools/Tools]]"
---

# Amass

[Amass](https://github.com/lgandx/Responder) —
In-depth attack surface mapping and asset discovery

The [OWASP Amass Project](https://owasp.org/www-project-amass/)
has developed a framework to help information security professionals
perform network mapping of attack surfaces and external asset discovery
using open source intelligence gathering and reconnaissance techniques

The framework includes a collection engine for asset discovery,
an asset database for storage of findings,
and the Open Asset Model used by various tooling
to help understand attack surfaces

___

<!-- Install {{{-->
## Install

[Kali Tools](https://www.kali.org/tools/amass/)

```sh
sudo apt install amass
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Help and Usage Information

```sh
amass -h
```

```sh
amass --help
```

Discover subdomains for the specified target domain

```sh
amass enum -d <target_domain>
```

Discover subdomains for the specified target domain (*file input*)

```sh
amass enum -df <file>
```

Save the discovered subdomains in a specified output file

```sh
amass enum -d <target_domain> -o <out_file>
```

Brute Force Subdomain Enumeration

```sh
amass enum -d <target_domain> -brute -w <wordlist.txt>
```

Resolve discovered subdomains to their respective IP addresses
(*DNS resolution*)

```sh
amass resolve -d <target_domain>
```

Verbose Output

```sh
amass enum -d <target_domain> -v
```

Specify data sources to use during enumeration

```sh
amass enum -d <target_domain> -src
```

___
<!-- }}} -->
