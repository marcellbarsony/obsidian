---
id: Group Enumeration
aliases: []
tags:
  - Linux/Privesc/Group-Enumeration
links: "[[Privesc]]"
---

# Group Enumeration

Enumerate system groups

___

<!-- Enumerate {{{-->
## Enumerate

List all group names on the system and its assigned users

```sh
cat /etc/group
```

[getent](https://linux.die.net/man/1/getent) —
List members of a group

```sh
getent group sudo
```

___
<!-- }}} -->
