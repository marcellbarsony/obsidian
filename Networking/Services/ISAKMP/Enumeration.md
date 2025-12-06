---
id: Enumeration
aliases: []
tags:
  - Networking/Services/ISAKMP/Enumeration
---

# Enumeration

<!-- Fingerprinting {{{-->
## Fingerprinting

[ike-scan](https://linux.die.net/man/1/ike-scan) —
Discover and fingerprint IKE hosts (*IPsec VPN servers*)

Extract information
(*e.g., hashing format, encryption algorithms, etc.*)

```sh
ike-scan -M $target
```

Extract information aggressively
(*e.g., identity*)

```sh
ike-scan -M $target --aggressive
```

Extract the hash or preshared key

```sh
ike-scan -M -A $target --pskcrack=hash-ike.txt
```

<!-- Info {{{-->
> [!info]-
>
> - `-M`: Easy to read output
> - `-A`: Use Aggressive Mode
> - `--pskcrack`: Saves the PSK parameters for offline cracking
<!-- }}} -->

___
<!-- }}} -->

<!-- Hash Cracking {{{-->
## Hash Cracking

Crack the extracted hash

<!-- Hash Type {{{-->
> [!tip]- Hash Type
>
> [Hashcat - Example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
>
> - `5300` - `IKE-PSK MD5`
> - `5400` - `IKE-PSK SHA1`
<!-- }}} -->

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> ```sh
> /usr/share/wordlists/rockyou.txt
> ```
<!-- }}} -->

```sh
hashcat -m 5400 -a 0 hash-ike.txt <password_list>
```

<!-- }}} -->
