---
id: Enumeration
aliases: []
tags:
  - Networking/Services/MSSQL/Enumeration
---

# Enumeration

<!-- Checklist {{{-->
## Checklist

- [ ] [[Enumeration#Nmap|Nmap]]
- [ ] [[Enumeration#Metasploit|Metasploit]]
    - [ ] [[Enumeration#Without Credentials|Without Credentials]]
    - [ ] [[Enumeration#With Credentials|With Credentials]]
- [ ] [[Enumeration#Mssqlclient.py|mssqlclient.py]]

___

<!-- }}} -->

<!-- Nmap {{{-->
## Nmap

Service detection

```sh
nmap -p 1433 <target> -oA mssql-service-detection
```

[[General|MSSQL]] script scan

```sh
sudo nmap \
  -sV -p 1433 \
  --script "ms-sql-*" \
  --script-args 'mssql.instance-port=1433,mssql.username=sa,mssql.password="",mssql.instance-name=MSSQLSERVER' \
  <target> \
  -oA mssql-scripts-all
```

<!-- Info {{{-->
> [!info]-
>
> - `"ms-sql-*"`: Should be quoted so the shell won’t try to expand the `*`
>    (*some shells need the quotes*)
> - `mssql.password=""`: Set an empty password explicitly
> - `ms-sql-*`: Run every `ms-sql` script
>    (*including intrusive/disruptive checks*)
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> The following scan reveals the `hostname`, `database instance name`, `software
> verion of MSSQL` and `named pipes` are enabled.
>
> ```sh
> sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
> ```
> ```sh
> Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-08 09:40 EST
> Nmap scan report for 10.129.201.248
> Host is up (0.15s latency).
>
> PORT     STATE SERVICE  VERSION
> 1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000.00; RTM
> | ms-sql-ntlm-info: 
> |   Target_Name: SQL-01
> |   NetBIOS_Domain_Name: SQL-01
> |   NetBIOS_Computer_Name: SQL-01
> |   DNS_Domain_Name: SQL-01
> |   DNS_Computer_Name: SQL-01
> |_  Product_Version: 10.0.17763
>
> Host script results:
> | ms-sql-dac: 
> |_  Instance: MSSQLSERVER; DAC port: 1434 (connection failed)
> | ms-sql-info: 
> |   Windows server name: SQL-01
> |   10.129.201.248\MSSQLSERVER: 
> |     Instance name: MSSQLSERVER
> |     Version: 
> |       name: Microsoft SQL Server 2019 RTM
> |       number: 15.00.2000.00
> |       Product: Microsoft SQL Server 2019
> |       Service pack level: RTM
> |       Post-SP patches applied: false
> |     TCP port: 1433
> |     Named pipe: \\10.129.201.248\pipe\sql\query
> |_    Clustered: false
>
> Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
> Nmap done: 1 IP address (1 host up) scanned in 8.52 seconds
> ```
<!-- }}} -->

___

<!-- }}} -->

<!-- Metasploit {{{-->
## Metasploit

Scan MSSQL service with [[Metasploit]]

<!-- Without Credentials {{{-->
### Without Credentials

MSSQL Ping Utility
([mssql_ping](https://www.rapid7.com/db/modules/auxiliary/scanner/mssql/mssql_ping/))

```sh
msf > use auxiliary/scanner/mssql/mssql_ping
```

<!-- Example {{{-->
> [!example]-
>
> 1. [[Metasploit#Launch Metasploit|Launch Metasploit]]
>
> 2. [[Metasploit#Search Exploit|Search scanner]]
>
> <!-- Example {{{-->
> > [!example]-
> >
> > ```sh
> > search type:auxiliary scanner
> > ```
> >
> > > [!warning]
> > >
> > > This may produce a long list
> > >
> >
> > Filter auxiliary scanners by service:
> > show all MSSQL-related modules:
> >
> > - `auxiliary/scanner/mssql/mssql_ping`
> > - `auxiliary/admin/mssql/mssql_login`
> > - `auxiliary/admin/mssql/mssql_exec`
> > - `auxiliary/admin/mssql/mssql_enum`
> > - `auxiliary/admin/mssql/mssql_sql`
> > - `auxiliary/admin/mssql/mssql_ntlm_stealer`
> >
> > ```sh
> > search type:auxiliary name:mssql
> > ```
> >
> > Narrow the findigs further
> >
> > ```sh
> > search type:auxiliary scanner mssql
> > ```
> <!-- }}} -->
>
> 3. [[Metasploit#Select Exploit|Select scanner]]
>
> <!-- Example {{{-->
> > [!example]-
> >
> > ```sh
> > msf6 > use auxiliary/scanner/mssql/mssql_ping
> > ```
> <!-- }}} -->
>
> 4. [[Metasploit#Show Options|Show options]]
>
> 5. [[Metasploit#Set Options|Set options]]
>
> <!-- Example {{{-->
> > [!example]-
> >
> > ```sh
> > msf6 auxiliary(scanner/mssql/mssql_ping) > set RHOSTS 10.129.201.248
> > ```
> >
> > **Optional**: If non-standard
> >
> > ```sh
> > msf6 auxiliary(scanner/mssql/mssql_ping) > set RPORT 1433
> > ```
> >
> > **Optional**: Speed-up scan
> >
> > ```sh
> > msf6 auxiliary(scanner/mssql/mssql_ping) > set THREADS 10
> > ```
> <!-- }}} -->
>
> 6. [[Metasploit#Check Exploit|Check Module]]
>
> 7. [[Metasploit#Run Exploit|Run Module]]
>
> <!-- Example {{{-->
> > [!example]-
> >
> >```sh
> >msf6 auxiliary(scanner/mssql/mssql_ping) > run
> >```
> >```sh
> >[*] 10.129.201.248:       - SQL Server information for 10.129.201.248:
> >[+] 10.129.201.248:       -    ServerName      = SQL-01
> >[+] 10.129.201.248:       -    InstanceName    = MSSQLSERVER
> >[+] 10.129.201.248:       -    IsClustered     = No
> >[+] 10.129.201.248:       -    Version         = 15.0.2000.5
> >[+] 10.129.201.248:       -    tcp             = 1433
> >[+] 10.129.201.248:       -    np              = \\SQL-01\pipe\sql\query
> >[*] 10.129.201.248:       - Scanned 1 of 1 hosts (100% complete)
> >[*] Auxiliary module execution completed
> >```
> <!-- }}} -->
<!-- }}} -->

MSSQL Login Utility
([mssql_login](https://www.rapid7.com/db/modules/auxiliary/scanner/mssql/mssql_login/))

```sh
msf > use auxiliary/scanner/mssql/mssql_login
```

<!-- Example {{{-->
> [!example]-
>
> Query the MSSQL instance for a specific user/pass
> (*default is sa with blank*)
>
> ```sh
> msf > use auxiliary/scanner/mssql/mssql_login
> msf auxiliary(mssql_login) > show actions
>     ...actions...
> msf auxiliary(mssql_login) > set ACTION < action-name >
> msf auxiliary(mssql_login) > show options
>     ...show and set options...
> msf auxiliary(mssql_login) > run
> ```
<!-- }}} -->


<!-- }}} -->

<!-- With Credentials {{{-->
### With Credentials

> [!tip]
>
> Set `USERNAME`, `RHOSTS` and `PASSWORD`
>
> Set `DOMAIN` and `USE_WINDOWS_AUTHENT` if domain is used


Microsoft SQL Server NTLM Stealer
([mssql_ntlm_stealer](https://www.rapid7.com/db/modules/auxiliary/admin/mssql/mssql_ntlm_stealer/))

```sh
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer
```

> [!warning]
>
> Run Responder before executing

Enumeration

- `auxiliary/admin/mssql/mssql_exec`
- `auxiliary/admin/mssql/mssql_enum`
- `auxiliary/admin/mssql/mssql_sql`

Info gathering

```sh
msf> use admin/mssql/mssql_enum #Security checks
```
```sh
msf> use admin/mssql/mssql_enum_domain_accounts
```
```sh
msf> use admin/mssql/mssql_enum_sql_logins
```
```sh
msf> use auxiliary/admin/mssql/mssql_findandsampledata
```
```sh
msf> use auxiliary/scanner/mssql/mssql_hashdump
```
```sh
msf> use auxiliary/scanner/mssql/mssql_schemadump
```

Search for insteresting data

```sh
msf> use auxiliary/admin/mssql/mssql_findandsampledata
```
```sh
msf> use auxiliary/admin/mssql/mssql_idf
```

Privesc

```sh
msf> use exploit/windows/mssql/mssql_linkcrawler
```
```sh
msf> use admin/mssql/mssql_escalate_execute_as #If the user has IMPERSONATION privilege, this will try to escalate
```
```sh
msf> use admin/mssql/mssql_escalate_dbowner #Escalate from db_owner to sysadmin
```

Code execution

```sh
msf> use admin/mssql/mssql_exec #Execute commands
```
```sh
msf> use exploit/windows/mssql/mssql_payload #Uploads and execute a payload
```

Add new admin user from meterpreter session

```sh
msf> use windows/manage/mssql_local_auth_bypass
```

<!-- }}} -->

___

<!-- }}} -->

<!-- Mssqlclient.py {{{-->
## Mssqlclient.py

[Impacket's mssqlclient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py)
allows to remotely connect and to the MSSQL server using Transact-SQL
([T-SQL](https://learn.microsoft.com/en-us/sql/t-sql/language-reference?view=sql-server-ver17))

```sh
python3 mssqlclient.py <user>@<target> -windows-auth
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
> ```
> ```sh
> Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
>
> Password:
> [*] Encryption required, switching to TLS
> [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
> [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
> [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
> [*] INFO(SQL-01): Line 1: Changed database context to 'master'.
> [*] INFO(SQL-01): Line 1: Changed language setting to us_english.
> [*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
> [!] Press help for extra shell commands
> ```
>
> ```sql
> SQL> select name from sys.databases
> ```
> ```sh
> name
>
> --------------------------------------------------------------------------------------
>
> master
>
> tempdb
>
> model
>
> msdb
>
> Transactions
> ```
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> Valid credentials required
<!-- }}} -->

___

<!-- }}} -->
