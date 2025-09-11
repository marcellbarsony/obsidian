---
id: checklist
aliases: []
tags:
  - Linux/Privesc
links: "[[Linux]]"
---

# Linux Privilege Escalation

## Enumeration Tools

- [ ] [[Linux/Privesc/Enumeration Tools|Enumeration Tools]]
    - [ ] [[Linux/Privesc/Enumeration Tools#Enumeration Scripts|Enumeration Scripts]]
        - [ ] [[Linux/Privesc/Enumeration Tools#Linpeas|LinPEAS]]
        - [ ] [[Linux/Privesc/Enumeration Tools#Linux Exploit Suggester|Linux Exploit Suggester]]
        - [ ] [[Linux/Privesc/Enumeration Tools#LinEnum|LinEnum]] (*deprecated*)
        - [ ] [[Linux/Privesc/Enumeration Tools#linuxprivchecker|linuxprivchecker]] (*deprecated*)
    - [ ] [[Linux/Privesc/Enumeration Tools#Manual Enumeration|Manual Enumeration]]

## System Information

- [ ] [[System Information]]
    - [ ] [[System Information#PATH|PATH]]
    - [ ] [[System Information#Kernel Exploits|Kernel Exploits]]
        - [ ] [[Kernel Exploits#Kernel Version|Kernel Version]]
        - [ ] [[Kernel Exploits#Public Exploits|Public Exploits]]
            - [ ] [[Kernel Exploits#DirtyCow (CVE-2016-5195)|DirtyCow (CVE-2016-5195)]]
            - [ ] [[Kernel Exploits#DirtyPipe (CVE-2022-0847)|DirtyPipe (CVE-2022-0847)]]

## User Enumeration

- [ ] [[User Enumeration]]
    - [ ] [[User Enumeration#User & Group|User & Group]]
        - [ ] [[User Enumeration#User|User]]
            - [ ] [[User Enumeration#whoami|whoami]]
            - [ ] [[User Enumeration#Home directory|Home directory]]
        - [ ] [[User Enumeration#Group|Group]]
            - [ ] [[User Enumeration#id|id]]
    - [ ] [[User Enumeration#Sudo|Sudo enumeration]]
        - [ ] [[User Enumeration#Sudo commands|Sudo commands]]
        - [ ] [[User Enumeration#Sudo version|Sudo version]]
        - [ ] [[User Enumeration#Sudo vulnerabilities|Sudo vulnerabilities]]

## Credential Hunting

- [ ] [[Credential Hunting]]
    - [ ] [[Credential Hunting#Home directory|Home directory]]
    - [ ] [[Credential Hunting#Shell|Shell]]
        - [ ] [[Credential Hunting#Bash|Bash]]
        - [ ] [[Credential Hunting#Zsh|Zsh]]
    - [ ] [[Credential Hunting#Environment Variables|Environment Variables]]
    - [ ] [[Credential Hunting#Web App Source Code|Web App Source Code]]

## Scheduled Tasks

- [ ] [[Scheduled Tasks]]
    - [ ] [[Scheduled Tasks#Discover Cron|Discover Cron]]
    - [ ] [[Scheduled Tasks#Cron Jobs|Cron Jobs]]

## SSH Keys

- [ ] [[SSH Keys]]
    - [ ] [[SSH Keys#Discover SSH Keys|Discover SSH Keys]]
    - [ ] [[SSH Keys#Copy SSH Keys|Copy SSH Keys]]
    - [ ] [[SSH Keys#Writeable SSH directory|Writeable SSH directory]]

## Installed Software

- [ ] [[Software Vulnerability]]
