---
id: Subbrute
aliases: []
tags:
  - Networking/Services/DNS/Tools/Subbrute
links: "[[Webapp/Enumeration/General|General]]"
---

# Subbrute

[Subbrute](https://github.com/TheRook/subbrute)
is a DNS meta-query spider that enumerates DNS records, and subdomains

<!-- Installation {{{-->
## Installation

[GitHub](https://github.com/TheRook/subbrute)

```sh
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

```sh
cd subbrute
```

```sh
./subbrute.py $target -s ./names.txt -r ./resolvers.txt
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> echo "ns1.inlanefreight.com" > ./resolvers.txt
> ```
> ```sh
> ./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt
> ```
> ```sh
> Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
> inlanefreight.com
> ns2.inlanefreight.com
> www.inlanefreight.com
> ms1.inlanefreight.com
> support.inlanefreight.com
>
> <SNIP>
> ```
>
<!-- }}} -->

___
<!-- }}} -->
