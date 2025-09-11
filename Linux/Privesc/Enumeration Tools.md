---
id: Enumeration Tools
aliases: []
tags:
  - Linux/Privesc/Enumeration-Tools
links: "[[Privesc]]"
---

# Enumeration Tools

## Enumeration Scripts

**NOTE**: Running enumeration scripts can generate a significant amount of
"noise," potentially triggering anti-virus or security monitoring software.
In some cases, it may be preferable to conduct manual enumeration instead.

- [GitHub - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## Linpeas

- [GitHub - PEASS-ng](https://github.com/peass-ng/PEASS-ng)
- [GitHub - PEASS-ng master](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)

### Usage

Download & Run as binary

```sh
# Download
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_linux_amd64 -O linpeas.sh

# Chmod
chmod +x linpeas.sh

# Run
./linpeas.sh
```

Download & Run from GitHub repository

```sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## Linux Exploit Suggester

- [Kali - Linux-Exploit-Suggester](https://www.kali.org/tools/linux-exploit-suggester/)
- [GitHub - linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)

### Usage

Quick download

```sh
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
```

Run

```sh
./linux-exploit-suggester.sh
```

## LinEnum

[**DEPRECATED**]

- [GitHub - LinEnum](https://github.com/rebootuser/LinEnum)

## linuxprivchecker

[**DEPRECATED**]

- [GitHub - linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)

# Manual Enumeration

Search the following direactories manually

- `/opt/`
- `/home/*`
- `/tmp`
- `/var`
