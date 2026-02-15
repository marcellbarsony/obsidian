---
id: Enumeration
aliases: []
tags:
  - Networking/Services/Oracle-TNS/Enumeration
---

# Enumeration

___

<!-- Service {{{-->
## Service

Enumerate Oracle-TNS service

<!-- Info {{{-->
> [!info]-
>
> ```sh
> oracle-tns      1521/tcp
> oracle-tns-alt  1526/tcp
> oracle-tns-alt  1541/tcp
> ```
>
<!-- }}} -->

Scan the default Oracle [[Oracle TNS/General#TNS Listener|TNS Listener]] port

```sh
sudo nmap -sV $target -p 1521 --open -oA oracle-tns-default
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap -p1521 -sV 10.129.204.235 --open
> ```
> ```sh
> Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 10:59 EST
> Nmap scan report for 10.129.204.235
> Host is up (0.0041s latency).
>
> PORT     STATE SERVICE    VERSION
> 1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
>
> Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
> Nmap done: 1 IP address (1 host up) scanned in 6.64 seconds
> ```
<!-- }}} -->

<!-- Banner {{{-->
### Banner

Connect to the TNS Listener to gather version and service information

[[Netcat]] — Grab banner and TNS version

```sh
nc -nv $target 1521
```

```sh
echo "(CONNECT_DATA=(COMMAND=version))" | nc $target 1521
```

[[Nmap]] — Banner grabbing

```sh
nmap -sV $target -p 1521 -oA oracle-tns-banner
```

[[Telnet/General|Telnet]] — Banner grabbing

```sh
telnet $target 1521
```

[tnslsnr](https://www.kali.org/tools/tnscmd10g/) —
Banner grabbing (*TNS ping*)

```sh
tnslsnr $target 1521
```

<!-- }}} -->

___
<!-- }}} -->

<!-- SID Enumeration {{{-->
## SID Enumeration

The SID ([[Networking/Services/Oracle TNS/General#System Identifier|System Identifier]])
is required to connect to Oracle databases and can be brute-forced

<!-- Tip - Default SIDs {{{-->
> [!tip]- Default SIDs
>
> Common default SIDs
>
> - `ORCL`
> - `XE`
> - `EXDB`
> - `PROD`
> - `DEV`
> - `TEST`
> - `DB11G`
> - `DB12C`
<!-- }}} -->

[[Nmap]] — SID enumeration

```sh
sudo nmap -sV $target -p 1521 --open --script oracle-sid-brute -oA oracle-sid-brute
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap -p 1521 -sV 10.129.204.235 --open --script oracle-sid-brute
> ```
> ```sh
> Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 11:01 EST
> Nmap scan report for 10.129.204.235
> Host is up (0.0044s latency).
>
> PORT     STATE SERVICE    VERSION
> 1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
> | oracle-sid-brute: 
> |_  XE
>
> Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
> Nmap done: 1 IP address (1 host up) scanned in 55.40 seconds
> ```
<!-- }}} -->

[[Pentest/Tools/Metasploit/Metasploit]] — [Oracle TNS Listener SID Enumeration](https://www.rapid7.com/db/modules/auxiliary/scanner/oracle/sid_enum/)

```sh
use auxiliary/scanner/oracle/sid_enum
```

> [!example]-
>
>
> ```sh
> msf > use auxiliary/scanner/oracle/sid_enum
> msf auxiliary(sid_enum) > show actions
>     ...actions...
> msf auxiliary(sid_enum) > set ACTION < action-name >
> msf auxiliary(sid_enum) > show options
>     ...show and set options...
> msf auxiliary(sid_enum) > run
> ```

[[#ODAT]] — SID enumeration

```sh
odat sidguesser -s $target -p 1521
```

[sidguesser](https://www.kali.org/tools/sidguesser/) —
SID enumeration

```sh
sidguess -i $target -d /usr/share/wordlists/metasploit/unix_users.txt
```

___

<!-- }}} -->

<!-- ODAT {{{-->
## ODAT

[[ODAT]] ([Oracle Database Attacking Tool](https://github.com/quentinhardy/odat))
can retrieve database names, versions, user accounts,
vulnerabilities and misconfigurations

```sh
./odat.py all -s $target
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ./odat.py all -s 10.129.204.235
> ```
>
> The scan has found valid credentials: `scott`:`tiger`
>
> ```sh
> [+] Checking if target 10.129.204.235:1521 is well configured for a connection...
> [+] According to a test, the TNS listener 10.129.204.235:1521 is well configured. Continue...
>
> ...SNIP...
>
> [!] Notice: 'mdsys' account is locked, so skipping this username for password           #####################| ETA:  00:01:16 
> [!] Notice: 'oracle_ocm' account is locked, so skipping this username for password       #####################| ETA:  00:01:05 
> [!] Notice: 'outln' account is locked, so skipping this username for password           #####################| ETA:  00:00:59
> [+] Valid credentials found: scott/tiger. Continue...
>
> ...SNIP...
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- SQL Plus {{{-->
## SQL Plus

[[SQL Plus]]

<!-- Log In {{{-->
### Log In

Log in as regular user

```sh
sqlplus <username>/<password>@$target/XE
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sqlplus scott/tiger@10.129.204.235/XE
> ```
> ```sh
> SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:19:21 2023
> Version 21.4.0.0.0
>
> Copyright (c) 1982, 2021, Oracle. All rights reserved.
>
> ERROR:
> ORA-28002: the password will expire within 7 days
>
>
>
> Connected to:
> Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
>
> SQL>
> ```
<!-- }}} -->

Log in the regular user as `sysdba` (*System Database Admin*)

```sh
sqlplus <user>/<password>@$target/XE as sysdba
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sqlplus scott/tiger@10.129.204.235/XE as sysdba
> ```
> ```sh
> SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:32:58 2023
> Version 21.4.0.0.0
>
> Copyright (c) 1982, 2021, Oracle. All rights reserved.
>
>
> Connected to:
> Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
>
> ```
> ```sh
> SQL> select * from user_role_privs;
> ```
> ```sh
>
> USERNAME                       GRANTED_ROLE                   ADM DEF OS_
> ------------------------------ ------------------------------ --- --- ---
> SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
> SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
> SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO
> SYS                            AQ_USER_ROLE                   YES YES NO
> SYS                            AUTHENTICATEDUSER              YES YES NO
> SYS                            CONNECT                        YES YES NO
> SYS                            CTXAPP                         YES YES NO
> SYS                            DATAPUMP_EXP_FULL_DATABASE     YES YES NO
> SYS                            DATAPUMP_IMP_FULL_DATABASE     YES YES NO
> SYS                            DBA                            YES YES NO
> SYS                            DBFS_ROLE                      YES YES NO
>
> USERNAME                       GRANTED_ROLE                   ADM DEF OS_
> ------------------------------ ------------------------------ --- --- ---
> SYS                            DELETE_CATALOG_ROLE            YES YES NO
> SYS                            EXECUTE_CATALOG_ROLE           YES YES NO
> ...SNIP...
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Finger {{{-->
## Finger

If the [finger service](https://en.wikipedia.org/wiki/Finger_(protocol))
is active on the same host as the [[Networking/Services/Oracle TNS/General#TNS Listener|TNS listener]],
and the Oracle OS account (often just `oracle`) is known,
the **finger** output can leak:

- The exact home directory (e.g., `/home/oracle`, `/u01/app/oracle`, etc.)
- The shell and sometimes system info
- Possibly hints about the Oracle software path or environment variables

> [!info]-
>
> This is valuable reconnaissance material:
>
> - The home directory path often matches Oracle installation paths
> - Knowing where Oracle is installed helps craft local privilege escalation,
>   file system attacks, or configuration abuse
> - Combined with other leaks (e.g.,
>   [[Networking/Services/Oracle TNS/General#Default Password|default listener password]] or unprotected
>   `listener.ora`), an attacker could manipulate the TNS listener
>   [[Networking/Services/Oracle TNS/General#TNS Listener|TNS listener]] or connect directly to the database


```sh
finger oracle@$target
```

<!-- Exmaple {{{-->
> [!example]-
>
> Simple (Unix)
>
> ```sh
> finger oracle@10.129.204.235
> ```
>
> Raw TCP (works when **finger** client is missing)
>
> ```sh
> printf "oracle\r\n" | nc 10.129.204.235 79
> ```
>
> ```sh
> echo "oracle" | nc 10.129.204.235 79
> ```
>
> Telnet interactive
>
> ```sh
> telnet 10.129.204.235 79
> # then type: oracle<Enter>
> ```
<!-- }}} -->

___

<!-- }}} -->
