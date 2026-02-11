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
        - [ ] [[User#Home Directories|Home Directories]]
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

<!-- User Enumeration {{{-->
## Group Enumeration

- [ ] [[Group]]
    - [ ] [[Group#Enumerate|Enumerate]]

___
<!-- }}} -->

<!-- Enumeration Tools {{{-->
## Enumeration Tools

- [ ] [[LinPEAS|LinPEAS]]
    - [ ] [[LinPEAS#Linpeas|LinPEAS]]
    - [ ] [[LinPEAS#Linux Exploit Suggester|Linux Exploit Suggester]]
    - [ ] [[LinPEAS#LinEnum|LinEnum]]
    - [ ] [[LinPEAS#linuxprivchecker|linuxprivchecker]]
- [ ] [[LinPEAS#Manual Enumeration|Manual Enumeration]]

___
<!-- }}} -->

<!-- Credential Hunting {{{-->
## Credential Hunting

- [ ] [[Credential Hunting]]
    - [ ] [[Credential Hunting#Directories|Directories]]
        - [ ] [[Credential Hunting#Current Directory|Current Directory]]
        - [ ] [[Credential Hunting#Home Directory|Home Directory]]
        - [ ] [[Credential Hunting#Root Directory|Root Directory]]
        - [ ] [[Credential Hunting#TMP Directory|TMP Directory]]
        - [ ] [[Credential Hunting#Web App Root|Web App Root]]
    - [ ] [[Credential Hunting#Files|Files]]
        - [ ] [[Credential Hunting#Configuration Files|Configuration Files]]
        - [ ] [[Credential Hunting#Fstab|Fstab]]
        - [ ] [[Credential Hunting#Hidden Items|Hidden Items]]
        - [ ] [[Credential Hunting#Shell|Shell]]
            - [ ] [[Credential Hunting#Bash|Bash]]
            - [ ] [[Credential Hunting#Zsh|Zsh]]
    - [ ] [[Credential Hunting#Environment Variables|Environment Variables]]
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
    - [ ] [[System Information#Hostname|Hostname]]
    - [ ] [[System Information#Kernel Exploits|Kernel Exploits]]
        - [ ] [[System Information#Kernel Version|Kernel Version]]
        - [ ] [[System Information#Public Exploits|Public Exploits]]
            - [ ] [[System Information#DirtyCow (CVE-2016-5195)|DirtyCow (CVE-2016-5195)]]
            - [ ] [[System Information#DirtyPipe (CVE-2022-0847)|DirtyPipe (CVE-2022-0847)]]
    - [ ] [[System Information#Hardware Information|Hardware Information]]
        - [ ] [[System Information#CPU|CPU]]
    - [ ] [[System Information#Login Shells|Login Shells]]

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

<!-- Filesystem {{{-->
## Filesystem

- [ ] [[Filesystem]]
    - [ ] [[Filesystem#Filesystems|Filesystems]]
    - [ ] [[Filesystem#Block Devices|Block Devices]]

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

<!-- Software Vulnerability {{{-->
## Software Vulnerability

- [ ] [[Software Vulnerability]]
    - [ ] [[Software Vulnerability#Installed Software|Installed Software]]
    - [ ] [[Software Vulnerability#Security Software|Security Software]]

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

- [ ] [[Cron Jobs]]
    - [ ] [[Cron Jobs#Discover Cron|Discover Cron]]
    - [ ] [[Cron Jobs#Cron Jobs|Cron Jobs]]

___
<!-- }}} -->

<!-- Network {{{-->
## Network

- [ ] [[Network]]
    - [ ] [[Network#Network Information|Network Information]]
    - [ ] [[Network#ARP Cache|ARP Cache]]
    - [ ] [[Network#Routing Table|Routing Table]]

___
<!-- }}} -->
