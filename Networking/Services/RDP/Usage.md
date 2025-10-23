---
id: Usage
aliases: []
tags:
  - Networking/Services/RDP/Usage
links:
  [[Services]]
---

# Usage

<!-- Connect {{{-->
## Connect

Using mstsc (*Windows*)

<!-- Exmaple {{{-->
> [!example]-
>
> Basic connection
>
> ```sh
> mstsc /v:<target>
> ```
>
> With specific port
>
> ```sh
> mstsc /v:<target>:3389
> ```
>
> Full screen mode
>
> ```sh
> mstsc /v:<target> /f
> ```
>
> Admin mode
>
> ```sh
> mstsc /v:<target> /admin
> ```
>
> Save connection settings
>
> ```sh
> mstsc /v:<target> /save:connection.rdp
> ```
<!-- }}} -->

Using xfreerdp (*Linux*)

<!-- Example {{{-->
> [!example]-
>
> Basic connection
>
> ```sh
> xfreerdp /v:<target>
> ```
>
> With credentials
>
> ```sh
> xfreerdp /u:<username> /p:<password> /v:<target>
> ```
>
> With domain
>
> ```sh
> xfreerdp /u:<DOMAIN>\\ /p:<password> /v:<target>
> ```
>
> Full options
>
> ```sh
> xfreerdp /u:<username> /p:<password> /v:<target>:3389 \
>   /cert:ignore /size:1920x1080 +clipboard +drives
> ```
>
> Pass-the-Hash
>
> ```sh
> xfreerdp /u:<username> /pth:NTHASH /v:<target> /cert:ignore
> ```
>
> Dynamic resolution
>
> ```sh
> xfreerdp /u: /p:<password> /v:<target> /dynamic-resolution
> ```
<!-- }}} -->

Using rdesktop

<!-- Example {{{-->
> [!example]-
>
> Basic connection
>
> ```sh
> rdesktop <target>
> ```
>
> With credentials
>
> ```sh
> rdesktop -u <username> -p <password> <target>
> ```
>
> Full screen
>
> ```sh
> rdesktop -f -u <username> <target>
> ```
>
> Specific resolution
>
> ```sh
> rdesktop -g 1920x1080 -u <username> <target>
> ```
<!-- }}} -->

___

<!-- }}} -->
