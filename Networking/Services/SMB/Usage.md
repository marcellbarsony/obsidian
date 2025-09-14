---
id: smbclient
aliases:
  - smbclient
tags:
  - Networking/Services/SMB/Usage
links: "[[SMB]]"
---

# Smbclient

[Smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
is a FTP-like client used to access SMB/CIFS resources on servers, share files,
printers, serial ports, and communicate between nodes on a network.

- [WikiPedia - Server Message Block](https://en.wikipedia.org/wiki/Server_Message_Block)
- [Microsoft SMB Protocol and CIFS protocol overview](https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview)
- [Smbclient - Man](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)

<!-- Usage {{{-->
## Usage

### Options

- `-L`: List services
- `-N`: suppress password prompt
- `-U`: Connect as user with known credentials

### Linux

Connect to an anonymous share

```sh
smbclient //{target_ip}/anonymous
```

### Windows (UNC path)

Discover & connect to shares (Windows UNC path)

```sh
smbclient -N -L \\\\{target_ip}\\
```

Connect to a share

```sh
smbclient -N \\\\{target_ip}\\{share}
```

Example

```sh
smbclient -U bob \\\\10.129.42.253\\users
```
<!-- }}} -->

<!-- SMB Actions {{{-->
## SMB Actions

```sh
# Change directory
smb: \> cd

# List files
smb: \> dir

# Get file
smb: \> get <remote_file_name> [local_file_name]

# Exit
smb: \> exit
```
<!-- }}} -->
