---
id: smbclient
aliases: []
tags:
  - SMB
links: "[[SMB]]"
---

# Smbclient

Smbclient is a ftp-like client used to access SMB/CIFS resources on servers,
share files, printers, serial ports, and communicate between nodes on a network.

- [WikiPedia - Server Message Block](https://en.wikipedia.org/wiki/Server_Message_Block)
- [Microsoft SMB Protocol and CIFS protocol overview](https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview)
- [Smbclient - Man](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)

## Usage

<!-- Usage {{{-->
<details>
  <summary><b>Discover & Connect</b></summary>

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

</details>
___
<!-- }}} -->

<!-- Actions {{{-->
<details>
  <summary><b>SMB Actions</b></summary>

```sh
# Change directory
smb: \> cd

# List files
smb: \> dir

# Get file
smb: \> get <remote file name> [local file name]

# Exit
smb: \> exit
```
<!-- }}} -->
