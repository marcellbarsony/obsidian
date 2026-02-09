---
id: General
aliases: []
tags:
  - Networking/Services/SMB/General
links: "[[Networking/Services/General]]"
port:
  - 139
  - 445
---

# SMB

**SMB** (*[Server Message Block](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/f210069c-7086-4dc2-885e-861d837df688)*)
is a client-server protocol over TCP, designed for sharing files,
directories, and other resources
(*e.g., printers, routers, interfaces*)
over a network

___

<!-- NetBIOS (Port 139) {{{-->
## NetBIOS

The [[Networking/Services/NetBIOS/General|NetBIOS]] (**port 139**)
is a software protocol designed to enable applications, PCs, and Desktops
within a LAN to interact with network hardware
and facilitate the transmission of data across the network

___
<!-- }}} -->

<!-- SMB (Port 445) {{{-->
## SMB

The **SMB** protocol (**port 445**) provides shared access to
files, printers, and serial ports between nodes on a network

**SMB** over TCP port `445` allows direct TCP/IP transport without relying on
the NetBIOS layer (over TCP port `139`), enabling more efficient and modern file
sharing and remote administration within LANs and across domain environments

<!-- Versions {{{-->
### Versions

- SMB 1.0 (*CIFS*): Deprecated
- SMB 2.0 / 2.1: Fewer requests, Better performance
- SMB 3.0+: Encryption, Bigning improvements, Multichannel

<!-- Example {{{-->
> [!info]-
>
> | SMB Version | Supported | Features |
> | --- | --- | --- |
> | CIFS | Windows NT 4.0 | Communication via NetBIOS interface |
> | SMB 1.0 | Windows 2000 | Direct connection via TCP |
> | SMB 2.0 | Windows Vista, Windows Server 2008 | Performance upgrades, improved message signing, caching feature |
> | SMB 2.1 | Windows 7, Windows Server 2008 R2 | Locking mechanisms |
> | SMB 3.0 | Windows 8, Windows Server 2012 | Multichannel connections, end-to-end encryption, remote storage access |
> | SMB 3.0.2 | Windows 8.1, Windows Server 2012 R2 |
> | SMB 3.1.1 | Windows 10, Windows Server 2016 | Integrity checking, AES-128 encryption
<!-- }}} -->

<!-- }}} -->

<!-- Samba {{{-->
### Samba

**[Samba](https://www.samba.org/)** is an alternative implementation
of the **SMB server** developed for Unix-based operating systems,
that implements the Common Internet File System
(*[CIFS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/934c2faa-54af-4526-ac74-6a24d126724e)*)
network protocol (*often referred as SMB/CIFS*)

Display the Samba server's status

```
sudo smbstatus
```

Restart the SMB service (*required on configuration change*)

```sh
sudo systemctl restart smbd
```

<!-- }}} -->

___
<!-- }}} -->

<!-- RPC {{{-->
## RPC

The **Remote Procedure Call** ([RPC](https://www.geeksforgeeks.org/operating-systems/remote-procedure-call-rpc-in-operating-system/))
is a way for a program to run a function on another computer in a network
as if it were local

1. The client sends a request (with arguments) to the server
2. The server executes the function
3. The server sends back the results

___
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

[smb.conf](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html) —
The configuration file for the Samba suite is located at `/etc/samba/smb.conf`

To apply changes in the configuration, the service daemon must be restarted

<!-- Default Configuration {{{-->
### Default Configuration

Default configuration parameters and values

Global settings are defined under the `[global]` share, and can be overwritten
in individual shares (*e.g., `[printers]`, `[print$]`, etc.*)

> [!info]- Default Configuration
>
>| Setting                        | Description                                                      |
>| ------------------------------ | ---------------------------------------------------------------- |
>| `[sharename]`                  | Name of the network share                                        |
>| `workgroup = WORKGROUP/DOMAIN` | Workgroup that will appear when clients query                    |
>| `path = /path/here/`           | The directory to which user is to be given access                |
>| `server string = STRING`       | String that will show up when a connection is initiated          |
>| `unix password sync = yes`     | Synchronize UNIX password with the SMB password                  |
>| `usershare allow guests = yes` | Allow non-authenticated users to access defined share            |
>| `map to guest = bad user`      | Action when a user login request doesn't match a valid UNIX user |
>| `browseable = yes`             | Show share in the list of available shares                       |
>| `guest ok = yes`               | Allow connecting without using a password                        |
>| `read only = yes`              | Allow users to read files only                                   |
>| `create mask = 0700`           | Permissions set for newly created files                          |

<!-- }}} -->

<!-- Dangerous Settings {{{-->
### Dangerous Settings

Some of the settings enable sensitive options

> [!danger]- Dangerous Settings
>
>| Setting                     | Description                                                        |
>| --------------------------- | ------------------------------------------------------------------ |
>| `browseable = yes`          | Allow listing available shares in the current share                |
>| `read only = no`            | Forbid the creation and modification of files                      |
>| `writable = yes`            | Allow users to create and modify files                             |
>| `guest ok = yes`            | Allow connecting to the service without using a password           |
>| `enable privileges = yes`   | Honor privileges assigned to specific SID                          |
>| `create mask = 0777`        | What permissions must be assigned to the newly created files       |
>| `directory mask = 0777`     | What permissions must be assigned to the newly created directories |
>| `logon script = script.sh`  | What script needs to be executed on the user's login               |
>| `magic script = script.sh`  | Which script should be executed when the script gets closed        |
>| `magic output = script.out` | Where the output of the magic script needs to be stored            |
<!-- }}} -->

___
<!-- }}} -->
