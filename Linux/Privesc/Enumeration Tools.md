---
id: Enumeration Tools
aliases: []
tags:
  - Linux/Privesc/Enumeration-Tools
links: "[[Privesc]]"
---

<!-- Enumeration Tools {{{-->
# Enumeration Tools

<!-- Warning {{{-->
> [!warning]
>
> Running **Enumeration Scripts** can generate noise,
> potentially triggering anti-virus or security monitoring software
>
> > [!tip]
> >
> > In some cases, it may be preferable to conduct manual enumeration
<!-- }}} -->

<!-- Resources {{{-->
> [!info]- Resources
>
> - [GitHub - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
>
<!-- }}} -->

___

<!-- Linpeas {{{-->
## Linpeas

[PEASS-ng](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) —
Privilege Escalation Awesome Scripts SUITE (*with colors*)

<!-- Download {{{-->
### Download

[Latest release](https://github.com/peass-ng/PEASS-ng/releases) —
Download

```sh
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -O linpeas.sh
```

[Latest release](https://github.com/peass-ng/PEASS-ng/releases) —
Download & Run directly

```sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

Kali local script

```sh
/usr/share/peass/linpeas/linpeas.sh
```

<!-- }}} -->

<!-- Usage {{{-->
### Usage

1. Make the script executable

```sh
chmod +x linpeas.sh
```

2. Run

```sh
./linpeas.sh
```
<!-- }}} -->

___
<!-- }}} -->

<!-- Linux Exploit Suggester {{{-->
## Linux Exploit Suggester

[linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) —
Linux privilege escalation auditing tool

<!-- Download {{{-->
### Download

Download the [script](https://github.com/The-Z-Labs/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh)

```sh
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
```

Download the [script](https://github.com/The-Z-Labs/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh)
& Run directly from repository

```sh
curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh | sh
```

<!-- }}} -->

<!-- Usage {{{-->
### Usage

1. Make the script executable

```sh
chmod +x les.sh
```

2. Run

```sh
./les.sh
```

<!-- }}} -->

___
<!-- }}} -->

<!-- LinEnum {{{-->
## LinEnum

[LinEnum](https://github.com/rebootuser/LinEnum)

> [!warning] DEPRECATED

___
<!-- }}} -->

<!-- linuxprivchecker {{{-->
## linuxprivchecker

[linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)

> [!warning] DEPRECATED

___
<!-- }}} -->

<!-- }}} -->

<!-- Manual Enumeration {{{-->
# Manual Enumeration

Search directories manually

- `/opt/`
- `/home/*`
- `/tmp`
- `/var`

___
<!-- }}} -->
