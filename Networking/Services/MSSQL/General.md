---
id: General
aliases: []
tags:
  - Networking/Services/MSSQL/General
links: "[[Services]]"
port:
  - 1443
---

# MSSQL

**MSSQL** ([Microsoft SQL](https://www.microsoft.com/en-us/sql-server/sql-server-2019))
is Microsoft's SQL-based relational database management system, with native
support for [.NET](https://en.wikipedia.org/wiki/.NET_Framework).

___

<!-- Clients {{{-->
## Clients

<!-- SSMS {{{-->
### SSMS

**SSMS** (*[SQL Server Management Studio](https://learn.microsoft.com/en-us/ssms/install/install?view=sql-server-ver15)*)
is a client-side application that is commonly installed
with the **MSSQL** server for database management

<!-- Example {{{-->
> [!example]-
>
> **MSSQL Server Management Studio** application
>
> ![[ssms.webp]]
<!-- }}} -->

<!-- }}} -->

<!-- mssqliclient.py {{{-->
### mssqliclient.py

[[Impacket]]'s [mssqlclient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py)
is available on many pentesting distributions to install

```sh
impacket-mssqlclient
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> locate mssqlclient
> ```
> ```sh
> /usr/bin/impacket-mssqlclient
> /usr/share/doc/python3-impacket/examples/mssqlclient.py
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Other Clients {{{-->
### Other Clients

**MSSQL** databases can be accessed with other clients:

- [HeidiSQL](https://www.heidisql.com/)
- [mssql-cli](https://learn.microsoft.com/en-us/sql/tools/mssql-cli?view=sql-server-ver15)
- [SQL Server PowerShell](https://learn.microsoft.com/en-us/powershell/sql-server/sql-server-powershell?view=sqlserver-ps&viewFallbackFrom=sql-server-ver15)
- [SQLPro](https://www.macsqlclient.com/)

<!-- }}} -->

___
<!-- }}} -->

<!-- Database {{{-->
## Database

**MSSQL** has default system databases

<!-- Info {{{-->
> [!info]
>
> | Default System Database | Description | Important Tables |
> | ----------------------- | ----------- | ---------------- |
> | master                  | System configuration | `sys.databases`, `sys.server_principals` |
> | model                   | Template for new databases | N/A |
> | msdb                    | SQL Server Agent data | `sysjobs`, `sysschedules` |
> | tempdb                  | Temporary objects | N/A |
> | resource                | System objects included (*Read-only*) | N/A |
<!-- }}} -->

___
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

<!-- Default Configuration {{{-->
### Default Configuration

Connecting form the client-side is possible through [Windows Authentication](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview).
Windows will process the login request either via

- local SAM database
- or the domain controller (hosting Active Directory))

before allowing connectivity to the database management system.

Using Active Directory can be ideal for auditing activity and controlling access
in a Windows environment, but if an account is compromised, it could lead to
privilege escalation and lateral movement across a Windows domain environment.

Initially, the SQL service will likely run as `NT SERVICE\MSSQLSERVER`.

> [!example]-
>
> ![[ssms-connect.png]]

> [!warning]
>
> **Encryption is not enforced** by default

<!-- }}} -->

<!-- Dangerous Settings {{{-->
### Dangerous Settings

The following settings may expose the system to danger

- SSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used.
  It is possible to spoof self-signed certificates
- The use of [named pipes](https://learn.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15)
- Weak & default credentials on an enabled `sa` (*System Administrator*) account

<!-- }}} -->

___
<!-- }}} -->
