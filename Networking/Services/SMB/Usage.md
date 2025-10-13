---
id: Usage
aliases:
  - smbclient
tags:
  - Networking/Services/SMB/Usage
links: "[[SMB]]"
---

# Usage

<!-- Smbclient {{{-->
## Smbclient

[Smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
is a FTP-like client used to access SMB/CIFS resources on servers, share files,
printers, serial ports, and communicate between nodes on a network.

- [WikiPedia - Server Message Block](https://en.wikipedia.org/wiki/Server_Message_Block)
- [Microsoft SMB Protocol and CIFS protocol overview](https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview)
- [Smbclient - Man](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)

<!-- Connect {{{-->
### Connect

<!-- Linux {{{-->
#### Linux

Connect to server and list shares (Null session)

```sh
smbclient -N -L //<target_ip>
```

> [!info]-
>
> - `-N`: Null session / Anonymous access
> - `-L`: List shares


Connect to a share

```sh
smbclient //<target_ip>/<share>
```

> [!example]-
>
> ```sh
> smbclient //<target_ip>/anonymous
> ```
> ```sh
> smbclient //<target_ip>/IPC$
> ```

Connect to share as specified user

```sh
smbclient -U bob //10.129.14.128/users
```

> [!info]-
>
> - `-U`: Connect as user with known credentials

<!-- }}} -->

<!-- Windows {{{-->
#### Windows

Connect to server and list shares (*Windows UNC path*)

```sh
smbclient -N -L \\\\<target_ip>\\
```

<!-- Info {{{-->
> [!info]-
>
> - `-N`: Null session / Anonymous access
> - `-L`: List shares
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> The SMB host may block listing shares but still allow connections
>
> <!-- Example {{{-->
> > [!example]-
> >
> > Enumerate most common Windows shares
> >
> > ```sh
> > #/bin/bash
> >
> > ip='<TARGET_IP>'
> >
> > shares=('C$' 'D$' 'ADMIN$' 'IPC$' 'PRINT$' 'FAX$' 'SYSVOL' 'NETLOGON')
> >
> > for share in ${shares[*]}; do
> >     output=$(smbclient -U '%' -N \\\\$ip\\$share -c '')
> >
> >     if [[ -z $output ]]; then
> >         echo "[+] :: Creating a null session is possible for $share"
> >         # no output if command goes through, thus assuming that a session was created
> >     else
> >         echo $output
> >         # echo error message (e.g. NT_STATUS_ACCESS_DENIED or NT_STATUS_BAD_NETWORK_NAME)
> >     fi
> > done
> > ```
<!-- }}} -->

<!-- }}} -->

Connect to a share

```sh
smbclient -N \\\\<target_ip>\\<share>
```

<!-- Info {{{-->
> [!info]-
>
> - `-N`: Null session / Anonymous access
<!-- }}} -->

Connect to a share as specified user

```sh
smbclient -U bob \\\\<target_ip>\\users
```

<!-- Info {{{-->
> [!info]-
>
> - `-U`: Connect as user with known credentials
<!-- }}} -->


<!-- }}} -->

<!-- }}} -->

<!-- SMB Actions {{{-->
### SMB Actions

> [!example]-
>
> Change directory
>
> ```sh
> smb: \> cd
> ```
>
> List files
>
> ```sh
> smb: \> dir
> ```
>
> Get file
>
> ```sh
> smb: \> get <remote_file_name> [local_file_name]
> ```
>
> Execute local system command (`!`)
>
> ```sh
> smb: \> !ls
> ```
>
> Exit
>
> ```
> smb: \> exit
> ```
<!-- }}} -->

<!-- }}} -->
