---
id: checklist
aliases: []
tags: []
---

# Linux Privilege Escalation

Linpeas

- [ ] Run <a href="/linux/privesc/linpeas.md" target="_blank">linpeas.sh</a>

System information

- [ ] Get <a href="/linux/privesc/system-info.md#os-info" target="_blank">OS information</a>
- [ ] Check <a href="/linux/privesc/system-info.md#path" target="_blank">PATH</a> variable
- [ ] Get <a href="/linux/privesc/system-info.md#environment-variables" target="_blank">env</a> variables
- [ ] Search <a href="/linux/privesc/system-info.md#kernel-exploits" target="_blank">kernel exploits</a>
  - [ ] <a href="/linux/privesc/system-info.md#dirtycow-cve-2016-5195" target="_blank">DirtyCow</a> (CVE-2016-5195)

Sudo

- [ ] Check <a href="/linux/privesc/sudo/sudo.md#" target="_blank">sudo</a> vulnerabilities

Drives

- [ ] List mounted <a href="/linux/privesc/system-info.md#mounted-drives" target="_blank">drives</a>
- [ ] Check <a href="/linux/privesc/system-info.md#fstab" target="_blank">fstab</a> for credentials

Users

- [ ] <a href="/linux/privesc/user-info.md#whoami" target="_blank">whoami</a> - Check current user
- [ ] <a href="/linux/privesc/user-info.md#id" target="_blank">id</a>
- [ ] Chueck user's <a href="/linux/privesc/user-info.md#home-directory" target="_blank">home directory</a>
- [ ] Check <a href="/linux/privesc/user-info.md#shell-history" target="_blank">shell history</a>
- [ ] Retrieve <a href="/linux/privesc/user-info.md#clipboard-data" target="_blank">clipboard data</a>
