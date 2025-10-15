---
id: General
aliases: []
tags:
  - Networking/Services/SMB/General
links: "[[Services]]"
port:
  - 139
  - 445
---

# SMB

**SMB** ([Server Message Block](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/f210069c-7086-4dc2-885e-861d837df688))
is a client-server protocol over TCP, designed for sharing files, directories,
and other resources (*e.g., printers, routers, interfaces*) over a network.

<!-- NetBIOS (Port 139) {{{-->
## NetBIOS (Port 139)

The [[Networking/Services/NetBIOS/General|NetBIOS]] is a software protocol
designed to enable applications, PCs, and Desktops within a LAN to interact with
network hardware and facilitate the transmission of data across the network.

___

<!-- }}} -->

<!-- SMB (Port 445) {{{-->
## SMB (Port 445)

The **SMB** protocol operates over **port 445** to provide shared access to
files, printers, and serial ports between nodes on a network.

**SMB** over TCP port `445` allows direct TCP/IP transport without relying on
the NetBIOS layer (over TCP port `139`), enabling more efficient and modern file
sharing and remote administration within LANs and across domain environments.

___

<!-- }}} -->

<!-- Samba {{{-->
## Samba

**[Samba](https://www.samba.org/)** is an alternative implementation of the
**SMB server** developed for Unix-based operating systems, that implements the
Common Internet File System ([CIFS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/934c2faa-54af-4526-ac74-6a24d126724e))
network protocol (*often referred as SMB/CIFS*).

<!-- Service {{{-->
### Service

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
as if it were local.

1. The client sends a request (with arguments) to the server
2. The server executes the function
3. The server sends back the results

___

<!-- }}} -->

<!-- Configuration {{{-->
### Configuration

[smb.conf](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html) —
The configuration file for the Samba suite is located at `/etc/samba/smb.conf`

To apply changes in the configuration, the service daemon must be restarted

<!-- Default Configuration {{{-->
#### Default Configuration

Default configuration parameters and values

Global settings are defined under the `[global]` share, and can be overwritten
in individual shares (e.g., `[printers]`, `[print$]`, etc.).

> [!info]-
>
> **Default Configuration**
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
#### Dangerous Settings

Some of the settings enable sensitive options

> [!danger]-
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
