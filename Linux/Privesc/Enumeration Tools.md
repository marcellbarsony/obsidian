---
id: Enumeration Tools
aliases: []
tags:
  - Linux/Privesc/Enumeration-Tools
links: "[[Privesc]]"
---

# Enumeration Tools

> [!warning]
>
> Running **Enumeration Scripts** can generate noise,
> potentially triggering anti-virus or security monitoring software
>
> > [!tip]
> >
> > In some cases, it may be preferable to conduct manual enumeration

- [GitHub - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

___

<!-- Linpeas {{{-->
## Linpeas

[PEASS-ng](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) —
Privilege Escalation Awesome Scripts SUITE (*with colors*)

### Usage

1. Download the script

```sh
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_linux_amd64 -O linpeas.sh
```

2. Make the script executable

```sh
chmod +x linpeas.sh
```

3. Run as binary

```sh
./linpeas.sh
```

Download & Run directly from repository

```sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

<!-- }}} -->

<!-- Linux Exploit Suggester {{{-->
## Linux Exploit Suggester

[linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) —
Linux privilege escalation auditing tool

### Usage

1. Download

```sh
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
```

2. Run

```sh
./linux-exploit-suggester.sh
```

Download & Run directly from repository

```sh
curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh | sh
```

<!-- }}} -->

<!-- LinEnum {{{-->
## LinEnum

> [!warning]
>
> [LinEnum](https://github.com/rebootuser/LinEnum)
> is **DEPRECATED**

<!-- }}} -->

<!-- linuxprivchecker {{{-->
## linuxprivchecker

> [!warning]
>
> [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)
> is **DEPRECATED**

<!-- }}} -->

<!-- anual Enumeration {{{-->
# Manual Enumeration

Search the following direactories manually

- `/opt/`
- `/home/*`
- `/tmp`
- `/var`

<!-- }}} -->
