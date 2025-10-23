---
id: Rsync
aliases: []
tags:
  - Networking/Services/Rsync/General
port:
  - 873
links: "[[Services]]"
---

# General

Rsync ([Remote Sync](https://en.wikipedia.org/wiki/Rsync))
is a utility for transferring and synchronizing files
between a computers across network

## Modules

**Rsync Modules** (*or shares*) are named directories that the rsync daemon
exposes to clients.

Each module maps to a specific path on the server and has its own access rules
(*e.g., read/write permissions authentication requirements*)

Modules can optionally be protected by a password.
