---
id: checklist
aliases: []
tags:
  - Linux/Privesc
links: "[[Linux]]"
---

# Linux Privilege Escalation

## Enumeration Scripts

- [ ] [[Linux/Privesc/Enumeration Scripts|Enumeration scripts]]
    - [ ] [[Linux/Privesc/Enumeration Scripts#Linpeas|LinPEAS]]
    - [ ] [[Linux/Privesc/Enumeration Scripts#LinEnum|LinEnum]]
    - [ ] [[Linux/Privesc/Enumeration Scripts#linuxprivchecker|linuxprivchecker]]

## System information

- [ ] [[Kernel Exploits]]
    - [ ] [[Kernel Exploits#Kernel Version|Kernel Version]]
    - [ ] [[Kernel Exploits#Public Exploits|Public Exploits]]
    - [ ] [[Kernel Exploits#DirtyCow (CVE-2016-5195)|DirtyCow (CVE-2016-5195)]]

___

- [ ] Get <a href="/linux/privesc/system-info.md#os-info" target="_blank">OS information</a>
- [ ] Check <a href="/linux/privesc/system-info.md#path" target="_blank">PATH</a> variable
- [ ] Get <a href="/linux/privesc/system-info.md#environment-variables" target="_blank">env</a> variables

## User Privileges

- [ ] [[User Privileges]]
    - [ ] [[User Privileges#Sudo commands|Sudo commands]]
    - [ ] [[User Privileges#Sudo version|Sudo version]]
    - [ ] [[User Privileges#Sudo vulnerabilities|sudo vulnerabilities]]

## Drives

- [ ] List mounted <a href="/linux/privesc/system-info.md#mounted-drives" target="_blank">drives</a>
- [ ] Check <a href="/linux/privesc/system-info.md#fstab" target="_blank">fstab</a> for credentials

## Users

- [ ] <a href="/linux/privesc/user-info.md#whoami" target="_blank">whoami</a> - Check current user
- [ ] <a href="/linux/privesc/user-info.md#id" target="_blank">id</a>
- [ ] Chueck user's <a href="/linux/privesc/user-info.md#home-directory" target="_blank">home directory</a>
- [ ] Check <a href="/linux/privesc/user-info.md#shell-history" target="_blank">shell history</a>
- [ ] Retrieve <a href="/linux/privesc/user-info.md#clipboard-data" target="_blank">clipboard data</a>

## Installed Software

- [ ] Look for [[Vulnerable Software]]
