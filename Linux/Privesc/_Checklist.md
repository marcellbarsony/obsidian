---
id: _Checklist
aliases: []
tags:
  - Linux/Privesc/Checklist
---

# Linux Privilege Escalation

___


<!-- User Enumeration {{{-->
## User Enumeration

- [ ] [[User]]
    - [ ] [[User#User|User]]
        - [ ] [[User#Identify|Identify]]
    - [ ] [[User#Group|Group]]
        - [ ] [[User#id|id]]

___
<!-- }}} -->

<!-- Sudo Enumeration {{{-->
## Sudo Enumeration

- [ ] [[Sudo]]
    - [ ] [[Sudo#Commands|Commands]]
    - [ ] [[Sudo#Version|Version]]
    - [ ] [[Sudo#Vulnerabilities|Vulnerabilities]]

___
<!-- }}} -->

<!-- Enumeration Tools {{{-->
## Enumeration Tools

- [ ] [[Linux/Privesc/Enumeration Tools|Enumeration Tools]]
    - [ ] [[Linux/Privesc/Enumeration Tools#Linpeas|LinPEAS]]
    - [ ] [[Linux/Privesc/Enumeration Tools#Linux Exploit Suggester|Linux Exploit Suggester]]
    - [ ] [[Linux/Privesc/Enumeration Tools#LinEnum|LinEnum]]
    - [ ] [[Linux/Privesc/Enumeration Tools#linuxprivchecker|linuxprivchecker]]
- [ ] [[Linux/Privesc/Enumeration Tools#Manual Enumeration|Manual Enumeration]]

___
<!-- }}} -->

<!-- Credential Hunting {{{-->
## Credential Hunting

- [ ] [[Credential Hunting]]
    - [ ] [[Credential Hunting#Directory Contents|Directory Contents]]
        - [ ] [[Credential Hunting#Current Directory|Current Directory]]
        - [ ] [[Credential Hunting#Root Directory|Root Directory]]
        - [ ] [[Credential Hunting#Home Directory|Home Directory]]
    - [ ] [[Credential Hunting#Shell|Shell]]
        - [ ] [[Credential Hunting#Bash|Bash]]
        - [ ] [[Credential Hunting#Zsh|Zsh]]
    - [ ] [[Credential Hunting#Environment Variables|Environment Variables]]
    - [ ] [[Credential Hunting#Web App Source Code|Web App Source Code]]
- [ ] [[Credential Hunting#Found Secrets|Found Secrets]]

___
<!-- }}} -->

<!-- SSH Keys {{{-->
## SSH Keys

- [ ] [[SSH Keys]]
    - [ ] [[SSH Keys#Discover SSH Keys|Discover SSH Keys]]
        - [ ] [[SSH Keys#User|User]]
        - [ ] [[SSH Keys#root|/root]]
    - [ ] [[SSH Keys#Exfiltrate SSH private keys|Exfiltrate SSH private keys]]
    - [ ] [[SSH Keys#Writeable SSH directory|Writeable SSH directory]]

___
<!-- }}} -->

<!-- System Information {{{-->
## System Information

- [ ] [[System Information]]
    - [ ] [[System Information#PATH|PATH]]
    - [ ] [[System Information#Kernel Exploits|Kernel Exploits]]
        - [ ] [[System Information#Kernel Version|Kernel Version]]
        - [ ] [[System Information#Public Exploits|Public Exploits]]
            - [ ] [[System Information#DirtyCow (CVE-2016-5195)|DirtyCow (CVE-2016-5195)]]
            - [ ] [[System Information#DirtyPipe (CVE-2022-0847)|DirtyPipe (CVE-2022-0847)]]

___
<!-- }}} -->

<!-- System Files {{{-->
## System Files

- [ ] [[System Files]]
    - [ ] [[System Files#/etc/passwd|/etc/passwd]]
    - [ ] [[System Files#/etc/shadow|/etc/shadow]]
        - [ ] [[System Files#Readability|Readability]]
        - [ ] [[System Files#Writeability|Writeability]]
        - [ ] [[System Files#Ownership|Ownership]]

___
<!-- }}} -->

<!-- File System {{{-->
## File System

- [ ] [[File System]]
    - [ ] [[File System#Additional Drives|Additional Drives]]
        config files

___
<!-- }}} -->

<!-- File {{{-->
## File

- [ ] [[Directory & File]]
    - [ ] [[Directory & File#Directory Enumeration|Directory Enumeration]]
    - [ ] [[Directory & File#File Enumeration|File Enumeration]]
        - [ ] [[Directory & File#File|File Enumeration]]
        - [ ] [[Directory & File#Credentials|Credentials]]
        - [ ] [[Directory & File#Ownership|Ownership]]
        - [ ] [[Directory & File#Permissions|Permissions]]

___
<!-- }}} -->

<!-- Installed Software {{{-->
## Installed Software

- [ ] [[Software Vulnerability]]
    - [ ] [[Software Vulnerability#Linux|Linux]]
        - [ ] [[Software Vulnerability#Debian / Ubuntu|Debian / Ubuntu]]
        - [ ] [[Software Vulnerability#Fedora / RHEL / CentOS|Fedora / RHEL / CentOS]]
        - [ ] [[Software Vulnerability#Arch|Arch]]
    - [ ] [[Software Vulnerability#BSD]]
        - [ ] [[Software Vulnerability#FreeBSD|FreeBSD]]
        - [ ] [[Software Vulnerability#OpenBSD|OpenBSD]]
        - [ ] [[Software Vulnerability#NetBSD|NetBSD]]
    - [ ] [[Software Vulnerability#macOS|macOS]]

___
<!-- }}} -->

<!-- Processes {{{-->
## Processes

- [ ] [[Processes]]
    - [ ] [[Processes#Running Processes|Running Processes]]

___
<!-- }}} -->

<!-- Scheduled Tasks {{{-->
## Scheduled Tasks

- [ ] [[Scheduled Tasks]]
    - [ ] [[Scheduled Tasks#Discover Cron|Discover Cron]]
    - [ ] [[Scheduled Tasks#Cron Jobs|Cron Jobs]]

___
<!-- }}} -->

<!-- Network {{{-->
## Network

- [ ] [[Network]]
    - [ ] [[Network#ARP Table|ARP Table]]

___
<!-- }}} -->
