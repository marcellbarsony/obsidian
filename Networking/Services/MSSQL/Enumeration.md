---
id: Enumeration
aliases: []
tags:
  - Networking/Services/MSSQL/Enumeration
---

# Enumeration

___

<!-- Service {{{-->
## Service

[[Nmap]] — Service detection

```sh
nmap $target -p 1433 -oA mssql-service-detection
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap $target -p 1433 -oA mssql-service-detection
> ```
> ```sh
> Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-08 21:33 EST
> Nmap scan report for 10.129.203.12
> Host is up (0.049s latency).
>
> PORT     STATE SERVICE
> 1433/tcp open  ms-sql-s
>
> Nmap done: 1 IP address (1 host up) scanned in 0.28 seconds
> ```
>
> The MSSQL service is up
<!-- }}} -->

[[Nmap]] — Service Banner

```sh
nmap -sC -sV -Pn $target -p 1433
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap -sC -sV -Pn 10.10.10.125 -p 1433
> ```
>
> ```sh
> Host discovery disabled (-Pn). All addresses will be marked 'up', and scan times will be slower.
> Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-26 02:09 BST
> Nmap scan report for 10.10.10.125
> Host is up (0.0099s latency).
>
> PORT     STATE SERVICE  VERSION
> 1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM
> | ms-sql-ntlm-info: 
> |   Target_Name: HTB
> |   NetBIOS_Domain_Name: HTB
> |   NetBIOS_Computer_Name: mssql-test
> |   DNS_Domain_Name: HTB.LOCAL
> |   DNS_Computer_Name: mssql-test.HTB.LOCAL
> |   DNS_Tree_Name: HTB.LOCAL
> |_  Product_Version: 10.0.17763
> | ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
> | Not valid before: 2021-08-26T01:04:36
> |_Not valid after:  2051-08-26T01:04:36
> |_ssl-date: 2021-08-26T01:11:58+00:00; +2m05s from scanner time.
>
> Host script results:
> |_clock-skew: mean: 2m04s, deviation: 0s, median: 2m04s
> | ms-sql-info: 
> |   10.10.10.125:1433: 
> |     Version: 
> |       name: Microsoft SQL Server 2017 RTM
> |       number: 14.00.1000.00
> |       Product: Microsoft SQL Server 2017
> |       Service pack level: RTM
> |       Post-SP patches applied: false
> |_    TCP port: 1433
> ```
<!-- }}} -->

[[Nmap]] — [[MSSQL/General|MSSQL]] script scan

```sh
sudo nmap \
  -sV \
  $target \
  -p 1433 \
  --script "ms-sql-*" \
  --script-args 'mssql.instance-port=1433,mssql.username=sa,mssql.password="",mssql.instance-name=MSSQLSERVER' \
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

[[Metasploit]] — Scan MSSQL service

<!-- Without Credentials {{{-->
### Without Credentials

[MSSQL Ping Utility](https://www.rapid7.com/db/modules/auxiliary/scanner/mssql/mssql_ping/)

```sh
use auxiliary/scanner/mssql/mssql_ping
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
> > ```sh
> > msf6 auxiliary(scanner/mssql/mssql_ping) > run
> > ```
> > ```sh
> > [*] 10.129.201.248:       - SQL Server information for 10.129.201.248:
> > [+] 10.129.201.248:       -    ServerName      = SQL-01
> > [+] 10.129.201.248:       -    InstanceName    = MSSQLSERVER
> > [+] 10.129.201.248:       -    IsClustered     = No
> > [+] 10.129.201.248:       -    Version         = 15.0.2000.5
> > [+] 10.129.201.248:       -    tcp             = 1433
> > [+] 10.129.201.248:       -    np              = \\SQL-01\pipe\sql\query
> > [*] 10.129.201.248:       - Scanned 1 of 1 hosts (100% complete)
> > [*] Auxiliary module execution completed
> > ```
> <!-- }}} -->
<!-- }}} -->

[MSSQL Login Utility](https://www.rapid7.com/db/modules/auxiliary/scanner/mssql/mssql_login/)

```sh
use auxiliary/scanner/mssql/mssql_login
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

Info gathering

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf> use admin/mssql/mssql_enum
> ```
> ```sh
> msf> use admin/mssql/mssql_enum_domain_accounts
> ```
> ```sh
> msf> use admin/mssql/mssql_enum_sql_logins
> ```
> ```sh
> msf> use auxiliary/admin/mssql/mssql_findandsampledata
> ```
> ```sh
> msf> use auxiliary/scanner/mssql/mssql_hashdump
> ```
> ```sh
> msf> use auxiliary/scanner/mssql/mssql_schemadump
> ```
> ```sh
> msf> use auxiliary/admin/mssql/mssql_sql
> ```
<!-- }}} -->

Search for insteresting data

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf> use auxiliary/admin/mssql/mssql_findandsampledata
> ```
> ```sh
> msf> use auxiliary/admin/mssql/mssql_idf
> ```
<!-- }}} -->

Privilege Escalation (*Privesc*)

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf> use exploit/windows/mssql/mssql_linkcrawler
> ```
>
> Elevate privileges if the user has
> [[Privileges#SeImpersonatePrivilege|SeImpersonatePrivilege]]
>
> ```sh
> msf> use admin/mssql/mssql_escalate_execute_as
> ```
>
> Escalate from `db_owner` to `sysadmin`
>
> ```sh
> msf> use admin/mssql/mssql_escalate_dbowner
> ```
<!-- }}} -->

Code execution

<!-- Example {{{-->
> [!example]-
>
> Execute commands
>
> ```sh
> msf> use admin/mssql/mssql_exec
> ```
>
> Uploads and execute a payload
>
> ```sh
> msf> use exploit/windows/mssql/mssql_payload
> ```
<!-- }}} -->

Add new admin user from meterpreter session

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf> use windows/manage/mssql_local_auth_bypass
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
