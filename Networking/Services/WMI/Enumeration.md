---
id: Enumeration
aliases: []
tags:
  - Networking/Services/WinRM/Enumeration
---

# Enumeration

___

<!-- Service {{{-->
## Service

[[Impacket]] - [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) —
Enumerate the service

```sh
impacket-wmiexec.py <user>:"<password>"@<target_ip> "<target_hostname>"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> impacket-wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
> ```
> ```sh
> Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
>
> [*] SMBv3.0 dialect used
> ILF-SQL-01
> ```
<!-- }}} -->

___
<!-- }}} -->
