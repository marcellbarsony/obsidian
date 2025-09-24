---
id: Usage
aliases:
  - smbclient
tags:
  - Networking/Services/SMB/Usage
links: "[[SMB]]"
---

# Usage

## Smbclient

[Smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
is a FTP-like client used to access SMB/CIFS resources on servers, share files,
printers, serial ports, and communicate between nodes on a network.

- [WikiPedia - Server Message Block](https://en.wikipedia.org/wiki/Server_Message_Block)
- [Microsoft SMB Protocol and CIFS protocol overview](https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview)
- [Smbclient - Man](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)

<!-- Connect {{{-->
### Connect

#### Linux

Connect to an anonymous share

```sh
smbclient //{target_ip}/anonymous
```

Connect to server and list shares

```sh
smbclient -N -L //10.129.14.128
```

- `-N`: Null session / Anonymous access
- `-L`: List shares

Connect to share as specified user

```sh
smbclient -U bob //10.129.14.128/users
```

- `-U`: Connect as user with known credentials

#### Windows (UNC path)

Connect to server and list shares (Windows UNC path)

```sh
smbclient -N -L \\\\{target_ip}\\
```

- `-N`: Null session / Anonymous access
- `-L`: List shares

Connect to a share

```sh
smbclient -N \\\\{target_ip}\\{share}
```

- `-N`: Null session / Anonymous access

Connect to a share as specified user

```sh
smbclient -U bob \\\\10.129.42.253\\users
```

- `-U`: Connect as user with known credentials
<!-- }}} -->

<!-- SMB Actions {{{-->
### SMB Actions

```sh
# Change directory
smb: \> cd

# List files
smb: \> dir

# Get file
smb: \> get <remote_file_name> [local_file_name]

# Execute local system command (`!`)
smb: \> !ls

# Exit
smb: \> exit
```
<!-- }}} -->
