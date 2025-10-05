---
id: ACL
aliases: []
tags:
  - Networking/General/ACL
---

# Access Control List

**Access Control List** ([ACL](https://en.wikipedia.org/wiki/Access-control_list))
is a list of rules associated with a system resource — such as a file,
directory, or network interface — that defines who can access it and what
actions they can perform.

Each entry maps a subject (e.g. *user*, *group*, *process*) to a specific
operation (e.g., *read*, *write*, *execute*, *allow*, *deny*).

## Implementations

### Filesystem ACLs

**Filesystem ACLs** work as filters, managing access to files and directories.

> [!example]
>
> - **Linux**: POSIX ACLs on [ext4](https://en.wikipedia.org/wiki/Ext4) or
>  [XFS](https://en.wikipedia.org/wiki/XFS) filesystems
> - **Windows**: [NTFS](https://en.wikipedia.org/wiki/NTFS) ACLs managed through
>   Access Control Entries ([ACEs](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries))

### Networking ACLs

**Networking ACLs** manage access to a network by defining rules that instruct
devices (e.g. *firewalls*, *routers*, *switches*) on how to process traffic.

#### Standard

**Standard ACL** (range: 1-99 or 1300-1999) is using the source IP address only
to permit or deny the traffic, and do not distinguish between IP traffic
(e.g., *TCP*, *UDP*, *HTTPS*, etc.).

#### Extended

**Extended ACL** (range: 100-199 and 2000-2699) uses Source IP, Destination IP,
Source Port and Destination Port.
