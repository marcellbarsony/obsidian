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

___

<!-- Modules {{{-->
## Modules

**Modules** (*or shares*) are named directories that the rsync daemon
exposes to clients.

Each module maps to a specific path on the server and has its own access rules
(*e.g., read/write permissions, authentication requirements*).

**Modules** can be protected by a password optionally.

___

<!-- }}} -->

<!-- R-Services {{{-->
## R-Services

**R-Services** are a suite of services hosted to enable remote access
or issue commands between Unix hosts over TCP/IP ports
`512`, `513`, and `514`.

**R-Services** are utilizing [Pluggable Authentication Modules (PAM)](https://debathena.mit.edu/trac/wiki/PAM),
however, the `/etc/hosts.equiv` and `.rhosts` [[#Configuration|config files]]
are used to bypass user authentication.

**R-Services** are accessible through [[Usage#R-Commands|R-Commands]].

___

<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

The **configuration files** contain a list of trusted hosts
and is used to grant access to other systems on the network
without further authentication

- `/etc/hosts.equiv` (*global*)

> [!example]-
>
>
> ```sh
> cat /etc/hosts.equiv
> ```
> ```
> pwnbox cry0l1t3
> ```
>
> > [!info]
> >
> > File format: `<hostname> <local username>`


- `.rhosts` (*local*)

> [!example]-
>
> ```sh
> cat .rhosts
> ```
> ```sh
> htb-student     10.0.17.5
> +               10.0.17.10
> +               +
> ```
>
> > [!info]
> >
> > File format: `<user> <ip>`

___

<!-- }}} -->
