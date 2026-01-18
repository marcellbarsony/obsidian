---
id: General
aliases: ["Rejetto HTTP File Server"]
tags:
  - Networking/Services/HttpFileServer/General
port:
  - 80
---

# Rejetto HTTP File Server

[HFS - HTTP File Server](https://rejetto.com/hfs/) (*HttpFileServer*)
is a web file server for your computer.
Share folders or even a single file thanks to the virtual file system.

___

<!-- Vulnerabilities {{{-->
## Vulnerabilities

<!-- CVE-2014-6287 {{{-->
### CVE-2014-6287

[CVE-2014-6287](https://nvd.nist.gov/vuln/detail/CVE-2014-6287)

<!-- Info {{{-->
> [!info]-
>
> The `findMacroMarker` function in `parserLib.pas`
> in Rejetto HTTP File Server (*aks HFS or HttpFileServer*)
> `2.3x` before `2.3c` allows remote attackers
> to execute arbitrary programs via a `%00` sequence in a search action
>
<!-- }}} -->

[[Metasploit]] - [Rejetto HttpFileServer Remote Command Execution](https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec/)

```sh
use exploit/windows/http/rejetto_hfs_exec
```


<!-- }}} -->

<!-- CVE-2024-23692 {{{-->
### CVE-2024-23692

[CVE-2024-23692](https://nvd.nist.gov/vuln/detail/cve-2024-23692)

<!-- Info {{{-->
> [!info]-
>
> Rejetto HTTP File Server, up to and including version `2.3m`,
> is vulnerable to a template injection vulnerability.
> This vulnerability allows a remote, unauthenticated attacker
> to execute arbitrary commands on the affected system
> by sending a specially crafted HTTP request.
>
> As of the CVE assignment date, Rejetto HFS `2.3m`
> is no longer supported
>
<!-- }}} -->

[[Metasploit]] - [Rejetto HTTP File Server (HFS) Unauthenticated Remote Code Execution](https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_rce_cve_2024_23692/)

```sh
use exploit/windows/http/rejetto_hfs_rce_cve_2024_23692
```


<!-- }}} -->

<!-- }}} -->
