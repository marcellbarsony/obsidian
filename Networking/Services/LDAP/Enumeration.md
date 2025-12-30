---
id: Enumeration
aliases: []
tags:
  - Networking/Services/LDAP/Enumeration
links: "[[LDAP]]"
---

# Enumeration

___

<!-- Domain Groups {{{-->
## Domain Groups

[[NetExec]] — [Enumerate Domain Groups](https://www.netexec.wiki/ldap-protocol/enumerate-group-members)

Enumerate all gorups in the domain

```sh
nxc ldap $target -u <user> -p <password> --groups
```

Enumerate all members of a specific group via [[LDAP]]

```sh
nxc ldap $target -u <user> -p <password> --groups "Domain Admins"
```

___
<!-- }}} -->
