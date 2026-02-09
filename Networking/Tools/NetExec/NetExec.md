---
id: NetExec
aliases:
  - CrackMapExec
tags:
  - Networking/Tools/NetExec
links: "[[Networking/Tools/General]]"
---

# NetExec (Nm)

**NetExec** (*a.k.a nxc, formerly [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)*)
is a network service exploitation tool that helps automate assessing the
security of large networks

- [GitHub - Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)
- [NetExec Wiki](https://www.netexec.wiki/)


<!-- Installation {{{-->
## Installation

NetExec [Installation](https://www.netexec.wiki/getting-started/installation)

```sh
sudo apt install netexec
```

Install via [NetExec Wiki](https://www.netexec.wiki/)

<!-- Tip {{{-->
> [!tip]
>
> Using [pipx](https://github.com/pypa/pipx) to install NetExec is recommended.
> This allows to use `NetExec` and the `nxcdb` system-wide.
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo apt install pipx git
> ```
> ```sh
> pipx ensurepath
> ```
> ```sh
> pipx install git+https://github.com/Pennyw0rth/NetExec
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Protocols {{{-->
## Protocols

Selecting & Using a Protocol on NetExec

<!-- Example {{{-->
> [!example]-
> - smb
> - ssh
> - ldap
> - ftp
> - wmi
> - winrm
> - rdp
> - vnc
> - mssql
> - nfs
<!-- }}} -->

View a protocol's options

```sh
nxc <protocol> --help
```

Use a protocol's options

```sh
nxc <protocol> <options>
```

___
<!-- }}} -->
