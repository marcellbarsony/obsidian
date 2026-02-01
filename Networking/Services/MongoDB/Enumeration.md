---
id: Enumeration
aliases: []
tags:
  - Networking/Services/MongoDB/Enumeration
---

# Enumeration

___

<!-- Service {{{-->
## Service

Enumerate MongoDB service

[[Nmap]] — Service detection

```sh
nmap $target -p 27017,27018 -oA mongodb-service-detection
```

[[Nmap]] — Server information

```sh
nmap $target -p 27017 --script mongodb-info -oA mongodb-script-mongodb-info
```

[[Nmap]] — List databases

```sh
nmap $target -p 27017 --script mongodb-databases -oA mongodb-script-mongodb-databases
```

<!-- Banner {{{-->
### Banner

Grab MongoDB service banner

[[Netcat]] — Banner grabbing

```sh
nc -vn $target 27017
```
<!-- }}} -->

___
<!-- }}} -->

<!-- Vulnerabilities {{{-->
## Vulnerabilities

[[MongoDB/Exploitation#Mongobleed|Mongobleed]]
(*[CVE-2025-14847](https://nvd.nist.gov/vuln/detail/CVE-2025-14847)*)

[[Metasploit]] - [MongoDB Memory Disclosure (CVE-2025-14847) - Mongobleed](https://www.rapid7.com/db/modules/auxiliary/scanner/mongodb/cve_2025_14847_mongobleed/)

```sh
use auxiliary/scanner/mongodb/cve_2025_14847_mongobleed
```

<!-- Info {{{-->
> [!info]-
>
> This module exploits a memory disclosure vulnerability
> in MongoDB's zlib decompression handling (CVE-2025-14847).
>
> By sending crafted `OP_COMPRESSED` messages with
> inflated BSON document lengths,
> the server reads beyond the decompressed buffer
> and returns leaked memory contents in error messages
>
> The vulnerability allows unauthenticated remote attackers
> to leak server memory which may contain sensitive information
> (*e.g., credentials, session tokens, encryption keys,
> or other application data*)
>
<!-- }}} -->

___
<!-- }}} -->
