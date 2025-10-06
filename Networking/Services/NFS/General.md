---
id: NFS
aliases:
  - Network File System
tags:
  - Networking/Services/NFS/General
links: "[[Services]]"
ports:
    - 111
    - 2049
---

# Network File System (NFS)

**NFS** ([Network File System](https://en.wikipedia.org/wiki/Network_File_System))
is a network file system developed by Sun Microsystems and has the same purpose
as [[SMB]].

- **NFS** is used between Unix and Linux systems
- **NFS** clients cannot communicate directly with SMB servers

**NFS version 4.1** ([RFC 8881](https://datatracker.ietf.org/doc/html/rfc8881))
aims to provide protocol support to leverage cluster server deployments,
including the ability to provide scalable parallel acces to files distributed
across multiple servers (pNFS extension). NFS version 4.1 includes a session
trunking mechanism (aka. NFS multipathing).

<!-- Configuration {{{-->
## Configuration

The configuration file is located at `/etc/exports`, and the options are shown
in the [NFS server export table](https://manpages.ubuntu.com/manpages/questing/en/man5/exports.5.html)

### Default Configuration

The default `exports` file contains examples of configuring NFS shares

> [!info]-
>
> **Default Configuration**
>
>| Option             | Description
>| ------------------ | ------------------------------------------------------- |
>| `rw`               | Read and write permissions                              |
>| `ro`               | Read only permissions                                   |
>| `sync`             | Synchronous data transfer (A bit slower)                |
>| `async`            | Asynchronous data transfer (A bit faster)               |
>| `secure`           | Ports above 1024 will not be used                       |
>| `insecure`         | Ports above 1024 will be used                           |
>| `no_subtree_check` | This option disables the checking of subdirectory trees |
>| `root_squash`      | Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents root from accessing files on an NFS mount |

### Dangerous Settings

Some settings can be dangerous for the comapny infrastructure

> [!danger]-
>
> **Dangerous Settings**
>
>| Option           | Description                                           |
>| ---------------- | ----------------------------------------------------- |
>| `rw`             | Read and write permissions                            |
>| `insecure`       | Ports above 1024 will be used                         |
>| `nohide`         | If another file system was mounted below an exported directory, this directory is exported by its own exports entry |
>| `no_root_squash` | All files created by root are kept with the UID/GID 0 |
>| `no_all_squash`  | User identities are preserved across the system       |

The `insecure` option allows users to ues ports above 1024: The first 1024 ports
can only be used by `root`. This prevents the fact that no users can use sockets
above port 1024 for the NFS service and interact with it.
<!-- }}} -->
