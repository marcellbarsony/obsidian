---
id: Usage
aliases:
  - smbclient
tags:
  - Networking/Services/SMB/Usage
links: "[[SMB]]"
---

# Usage

___

<!-- Smbclient {{{-->
## Smbclient

[Smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
is a FTP-like client used to access
[SMB](https://en.wikipedia.org/wiki/Server_Message_Block)/
[CIFS](https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview)
resources on servers, share files, printers, serial ports,
and communicate between nodes on a network

<!-- Connect {{{-->
### Connect

<!-- Linux {{{-->
#### Linux

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
smbclient \\\\<target_ip>\\users -U "<username>"
```

<!-- Info {{{-->
> [!info]-
>
> - `-U`: Connect as user with known credentials
<!-- }}} -->

```sh
smbclient "\\\\<target_ip>\\" -U <username> -W <domain_name>
```

```sh
smbclient "\\\\<target_ip>\\" -U <username> -W <domain_name> --pw-nt-hash `hash`
```

<!-- Info {{{-->
> [!info]-
>
> - `-W <domain_name>`: NetBIOS/workgroup or Active Directory domain to use for the login
> - `--pw-nt-hash hash`: Use the supplied NT hash as the password
>   (*pass-the-hash style auth*)
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- SMB Actions {{{-->
### SMB Actions

Change directory

```sh
smb: \> cd
```

List files

```sh
smb: \> dir
```

Get file

```sh
smb: \> get <remote_file_name> [local_file_name]
```

Execute local system command

```sh
smb: \> !ls
```

Exit

```
smb: \> exit
```
<!-- }}} -->

___

<!-- }}} -->

<!-- Windows {{{-->
## Windows

<!-- GUI {{{-->
### GUI

Run Dialog — Interact with a shared folder

<!-- Example {{{-->
> [!example]-
>
> ![[windows-shared-folder.jpg]]
<!-- }}} -->

<!-- }}} -->

<!-- CMD {{{-->
### CMD

[dir](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir) —
List shared folder contents

```sh
dir \\<target>\<share>\
```

<!-- Example {{{-->
> [!example]-
>
> ```cmd
> C:\htb> dir \\192.168.220.129\Finance\
> ```
> ```sh
> Volume in drive \\192.168.220.129\Finance has no label.
> Volume Serial Number is ABCD-EFAA
>
> Directory of \\192.168.220.129\Finance
>
> 02/23/2022  11:35 AM    <DIR>          Contracts
>                0 File(s)          4,096 bytes
>                1 Dir(s)  15,207,469,056 bytes free
> ```
<!-- }}} -->

[net use](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155(v=ws.11)) —
Connect to a file share and and map its content to the drive letter `n`

```sh
net use n: \\<target>\<share>
```

```sh
net use n: \\<target>\<share> /user:<user> <password>
```

<!-- Example {{{-->
> [!example]-
>
> ```cmd
> C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123
> ```
> ```sh
> The command completed successfully.
> ```
<!-- }}} -->

<!-- }}} -->

<!-- PowerShell {{{-->
### PowerShell

[Get-ChildItem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem?view=powershell-7.5) —
List shared folder contents

```powershell
Get-ChildItem \\<target>\<share>\
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\
> ```
> ```sh
>     Directory: \\192.168.220.129\Finance
>
> Mode                 LastWriteTime         Length Name
> ----                 -------------         ------ ----
> d-----         2/23/2022   3:27 PM                Contracts
> ```
<!-- }}} -->

[New-PSDrive](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive?view=powershell-7.5) —
Connect to a file share and and map its content to the drive letter `n`

```sh
New-PSDrive -Name "N" -Root "\\<target>\<share>" -PSProvider "FileSystem"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
> ```
> ```sh
>
> Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
> ----           ---------     --------- --------      ----                                               ---------------
> N                                      FileSystem    \\192.168.220.129\Finance
> ```
<!-- }}} -->

To provide credentials, a
[PSCredential Object](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.4.0)
needs to be created

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> $username = 'plaintext'
> PS C:\htb> $password = 'Password123'
> PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
> PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
> PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
>
> Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
> ----           ---------     --------- --------      ----                                                              ---------------
> N                                      FileSystem    \\192.168.220.129\Finance
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
