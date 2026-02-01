---
id: enum4linux-ng
aliases: []
tags:
  - Networking/Services/SMB/Tools/enum4linux-ng
links: "[[SMB]]"
---

# enum4linux-ng

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
is the next generation version of [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)
(*a Windows/Samba enumeration tool*)
with additional features like JSON/YAML export

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
is a wrapper around the Samba tools `nmblookup`, `net`, `rpcclient`
and [[Usage#smbclient|smbclient]] that interacts with the exposed services
via [named pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes)

Aimed for security professionals and CTF players

<!-- Info {{{-->
> [!info]- Features
>
> - User Enumeration
> - Group Enumeration
> - Share Enumeration
> - Password Policy Retrieval
> - OS Information Discovery
> - Domain/Workgroup Information
> - RID Cycling
> - SID Enumeration
> - Printer Information
> - Null Session Exploitation
> - Credential-Based Enumeration
> - Verbose Output Options
> - Multiple Protocol Support
>
<!-- }}} -->

<!-- Info {{{-->
> [!info]- Data Sources
>
> - SMB Protocol
> - NetBIOS Protocol
> - MSRPC Protocol
> - SAMR (Security Account Manager Remote)
> - LSA (Local Security Authority)
> - Share Information
> - Domain Controllers
> - Windows Registry (Remote)
> - Active Directory (via RPC)
>
<!-- }}} -->


___

<!-- Install {{{-->
# Install

[Kali Tools](https://www.kali.org/tools/enum4linux-ng/)

```sh
sudo apt install enum4linux-ng
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Help and Usage Information

```sh
enum4linux -h
```

```sh
enum4linux --help
```

Dependency Check

<!-- Info {{{-->
> [!info]-
>
> Check if all required dependencies (smbclient, rpcclient, etc.)
> are installed and accessible
>
<!-- }}} -->

```sh
enum4linux -d
```


Basic Enumeration

<!-- Info {{{-->
> [!info]-
>
> Perform a basic enumeration of the target system,
> gathering general information about users, shares,
> and system configuration.
>
<!-- }}} -->

```sh
enum4linux $target
```

Full Enumeration

<!-- Info {{{-->
> [!info]-
>
> This command performs comprehensive enumeration using all available techniques,
> providing maximum information about the target system.
>
<!-- }}} -->

```sh
enum4linux -a $target
```

User Enumeration

<!-- Info {{{-->
> [!info]-
>
> This command specifically enumerates users on the target system,
> listing all local and domain user accounts.
>
<!-- }}} -->

```sh
enum4linux -U $target
```

Share Enumeration

<!-- Info {{{-->
> [!info]-
>
> This command lists all SMB shares available on the target system
> along with their permissions and access controls.
>
<!-- }}} -->

```sh
enum4linux -S $target
```

Group Enumeration

<!-- Info {{{-->
> [!info]-
>
> This command enumerates local and domain groups on the target system,
> including group memberships.
>
<!-- }}} -->

```sh
enum4linux -G $target
```

Password Policy

<!-- Info {{{-->
> [!info]-
>
> This command retrieves the password policy from the target system,
> including requirements and lockout settings.
>
<!-- }}} -->

```sh
enum4linux -P $target
```

OS Information

<!-- Info {{{-->
> [!info]-
>
> This command gathers operating system information including version,
> build number, and system architecture.
>
>
<!-- }}} -->

```sh
enum4linux -o $target
```

RID Cycling

<!-- Info {{{-->
> [!info]-
>
> This command performs RID cycling to enumerate users and groups
> through brute-forcing SIDs (Security Identifiers)
>
<!-- }}} -->

```sh
enum4linux -r $target
```

Detailed RID Cycling

<!-- Info {{{-->
> [!info]-
>
> This command performs detailed RID cycling with an extended range,
> discovering more users and groups through comprehensive SID enumeration.
>
<!-- }}} -->

```sh
enum4linux -R 500-550,1000-1050 $target
```

Authenticated Enumeration

<!-- Info {{{-->
> [!info]-
>
> This command performs enumeration using provided credentials,
> accessing information that requires authentication.
>
<!-- }}} -->

```sh
enum4linux -u <username> -p <password> $target
```

Domain Information

<!-- Info {{{-->
> [!info]-
>
> This command retrieves domain and workgroup information from the target system.
>
<!-- }}} -->

```sh
enum4linux -d $target
```

List Users via RID

<!-- Info {{{-->
> [!info]-
>
> This command enumerates users by iterating through RIDs,
> useful when other enumeration methods fail.
>
<!-- }}} -->

```sh
enum4linux -r -u <username> -p <password> $target
```

Printer Information

<!-- Info {{{-->
> [!info]-
>
> This command gathers information about network printers
> configured on the target system.
>
<!-- }}} -->

```sh
enum4linux -i $target
```

Group Member Information

<!-- Info {{{-->
> [!info]-
>
> This command retrieves detailed information about members of specific groups.
>
<!-- }}} -->

```sh
enum4linux -M $target
```

Share Access Check

<!-- Info {{{-->
> [!info]-
>
> This command checks which shares are accessible
> and attempts to list their contents.
>
<!-- }}} -->

```sh
enum4linux -s /usr/share/enum4linux/share-list.txt $target
```

Verbose Output

<!-- Info {{{-->
> [!info]-
>
> This command enables verbose output mode,
> displaying detailed information about enumeration operations and results.
>
<!-- }}} -->

```sh
enum4linux -v $target
```

Workgroup Detection

<!-- Info {{{-->
> [!info]-
>
> This command detects and displays the workgroup or domain name of the target system.
>
<!-- }}} -->

```sh
enum4linux -w $target
```

Known Usernames Check

<!-- Info {{{-->
> [!info]-
>
> This command checks for the existence of common
> or known usernames on the target system.
>
<!-- }}} -->

```sh
enum4linux -k <username> $target
```

___
<!-- }}} -->
