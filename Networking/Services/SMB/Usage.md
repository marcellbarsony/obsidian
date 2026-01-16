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
smbclient //$target/
```

```sh
smbclient //$target/[share]
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> smbclient //$target/anonymous
> ```
> ```sh
> smbclient //$target/IPC$
> ```
>
<!-- }}} -->

Connect to share as specified user

```sh
smbclient //$target/[share] -U <user>
```

```sh
smbclient //$target/[share] -U <user>%<password>
```

<!-- Info {{{-->
> [!info]-
>
> - `-U`: Connect as user with known credentials
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> smbclient -U SVC_TGS //$target/Users
> ```
>
> ```sh
> smbclient -U SVC_TGS%GPPstillStandingStrong2k18 //$target/Users
> ```
>
<!-- }}} -->

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
smbclient -N \\\\$target\\<share>
```

<!-- Info {{{-->
> [!info]-
>
> - `-N`: Null session / Anonymous access
<!-- }}} -->

Connect to a share as specified user

```sh
smbclient \\\\$target\\<share> -U "<user>"
```

<!-- Info {{{-->
> [!info]-
>
> - `-U`: Connect as user with known credentials
<!-- }}} -->

```sh
smbclient "\\\\$target\\" -U <user> -W <domain_name>
```

```sh
smbclient "\\\\$target\\" -U <user> -W <domain_name> --pw-nt-hash `hash`
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

<!-- Actions {{{-->
### Actions

Current directory

```sh
pwd
```

Change directory

```sh
cd
```

List files

```sh
ls
```

```sh
dir
```

Get file

```sh
get <remote_file> [local_file]
```

Put file

```sh
put <local_file> [remote_file]
```

Execute local system command

```sh
!ls
```

Exit

```
smb: \> exit
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> smb: \> exit
> ```
>
<!-- }}} -->


<!-- }}} -->

___
<!-- }}} -->

<!-- Linux {{{-->
## Linux

Linux (*UNIX*) machines can also mount and browse SMB shares,
whether the target server is Windows machine or Samba server

<!-- Impacket {{{-->
### Impacket

> [!todo]

[[Impacket]] - [PsExec](https://github.com/fortra/impacket/blob/master/examples/psexec.py) —
Python PsExec like functionality example using
[RemComSvc](https://github.com/kavika13/RemCom)

```sh
impacket-psexec <user>:'<password>'@$target
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> MarciPwns@htb[/htb]$ impacket-psexec administrator:'Password123!'@10.10.110.17
> ```
>
> ```sh
> Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
>
> [*] Requesting shares on 10.10.110.17.....
> [*] Found writable share ADMIN$
> [*] Uploading file EHtJXgng.exe
> [*] Opening SVCManager on 10.10.110.17.....
> [*] Creating service nbAc on 10.10.110.17.....
> [*] Starting service nbAc.....
> [!] Press help for extra shell commands
> Microsoft Windows [Version 10.0.19041.1415]
> (c) Microsoft Corporation. All rights reserved.
> ```
>
> ```sh
> C:\Windows\system32>whoami && hostname
> ```
>
> ```sh
> nt authority\system
> WIN7BOX
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Mount {{{-->
### Mount

Mount and browse SMB shares

1. Install [cifs-utils](https://www.kali.org/tools/cifs-utils/)

```sh
sudo apt install cifs-utils
```

2. Create a temporary mount directory

```sh
sudo mkdir /mnt/tmp
```

3. Mount the SMB share

```sh
sudo mount -t cifs -o username=<username>,password=<password>,domain=. //$target/<share> /mnt/ext
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> MarciPwns@htb[/htb]$ sudo mkdir /mnt/Finance
> ```
> ```sh
> MarciPwns@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
> ```
<!-- }}} -->

```sh
mount -t cifs //$target/<share> /mnt/ext -o credentials=/path/credentialfile
```

<!-- Credential File {{{-->
> [!info]- Credential File
>
> ```sh
> username=plaintext
> password=Password123
> domain=.
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> MarciPwns@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- NetExec {{{-->
## NetExec

<!-- Authenticate {{{-->
### Authenticate

```sh
nxc smb $target -u <user> -p '<password>'
```

```sh
nxc smb $target -u <user> -p '<password>' --local-auth
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE'
> ```
<!-- }}} -->

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
dir \\$target\<share>\
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
net use n: \\$target\<share>
```

```sh
net use n: \\$target\<share> /user:<user> <password>
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
Get-ChildItem \\$target\<share>\
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
Connect to a file share and and map its content to the drive letter `N`

```sh
New-PSDrive -Name "N" -Root "\\$target\<share>" -PSProvider "FileSystem"
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

[New-PSDrive](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive?view=powershell-7.5) —
Connect to a file share with credentials

<!-- Example {{{-->
> [!example]-
>
> Create a [PSCredential Object](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.4.0)
>
> ```powershell
> $username = 'user'
> ```
> ```powershell
> $password = 'Password123'
> ```
> ```powershell
> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
> ```
> ```powershell
> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
> ```
> ```powershell
> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
> ```
>
> ```powershell
> Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
> ----           ---------     --------- --------      ----                                                              ---------------
> N                                      FileSystem    \\192.168.220.129\Finance
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
