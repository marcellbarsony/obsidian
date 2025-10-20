---
id: Enumeration
aliases: []
tags:
  - Networking/Services/MySQL/Enumeration
---

# Enumeration

___

<!-- Configuration File {{{-->
## Configuration File

Often, the rights for the [[General#Configuration|configuration file]] of the
[[General#MySQL Database|MySQL databases]] are not assigned correctly.

> [!tip]
>
> If an attacker can read files or gain shell access, they may retrieve the file
> containing the MySQL username and password

___

<!-- }}} -->

<!-- Reconnaissance {{{-->
## Reconnaissance

<!-- Nmap {{{-->
### Nmap

Detect MySQL service

```sh
nmap -p 3306 <target> -oA mysql-service
```

Enumerate [[General#MySQL Database|MySQL Databases]] via
[[Nmap Scripting Engine|Nmap NSE]] scripts

```sh
sudo nmap -sC -sV -p3306 --script mysql* <target> -oA mysql-default-scripts
```

<!-- Info {{{-->
> [!info]-
>
> - `--script mysql*`: Run every NSE script related to MySQL
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap -sC -sV -p3306 --script mysql* 10.129.14.128 -oA mysql-default-scripts
> ```
> ```sh
> Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-21 00:53 CEST
> Nmap scan report for 10.129.14.128
> Host is up (0.00021s latency).
>
> PORT     STATE SERVICE     VERSION
> 3306/tcp open  nagios-nsca Nagios NSCA
> | mysql-brute:
> |   Accounts:
> |     root:<empty> - Valid credentials
> |_  Statistics: Performed 45010 guesses in 5 seconds, average tps: 9002.0
> |_mysql-databases: ERROR: Script execution failed (use -d to debug)
> |_mysql-dump-hashes: ERROR: Script execution failed (use -d to debug)
> | mysql-empty-password:
> |_  root account has empty password
> | mysql-enum:
> |   Valid usernames:
> |     root:<empty> - Valid credentials
> |     netadmin:<empty> - Valid credentials
> |     guest:<empty> - Valid credentials
> |     user:<empty> - Valid credentials
> |     web:<empty> - Valid credentials
> |     sysadmin:<empty> - Valid credentials
> |     administrator:<empty> - Valid credentials
> |     webadmin:<empty> - Valid credentials
> |     admin:<empty> - Valid credentials
> |     test:<empty> - Valid credentials
> |_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
> | mysql-info:
> |   Protocol: 10
> |   Version: 8.0.26-0ubuntu0.20.04.1
> |   Thread ID: 13
> |   Capabilities flags: 65535
> |   Some Capabilities: SupportsLoadDataLocal, SupportsTransactions, Speaks41ProtocolOld, LongPassword, DontAllowDatabaseTableColumn, Support41Auth, IgnoreSigpipes, SwitchToSSLAfterHandshake, FoundRows, InteractiveClient, Speaks41ProtocolNew, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, LongColumnFlag, SupportsCompression, ODBCClient, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
> |   Status: Autocommit
> |   Salt: YTSgMfqvx\x0F\x7F\x16\&\x1EAeK>0
> |_  Auth Plugin Name: caching_sha2_password
> |_mysql-users: ERROR: Script execution failed (use -d to debug)
> |_mysql-variables: ERROR: Script execution failed (use -d to debug)
> |_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
> MAC Address: 00:00:00:00:00:00 (VMware)
>
> Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
> Nmap done: 1 IP address (1 host up) scanned in 11.21 seconds
> ```
>
> > [!note]
> >
> > This scan is **false-positive** as the target MySQL server does not use an
> > empty password for the `root` user
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> The **scan results should be confirmed manually**
> as some of the information might turn out to be **false-positive**
<!-- }}} -->

<!-- }}} -->

<!-- Metasploit {{{-->
### Metasploit

MySQL Server Version Enumeration
([mysql_version](https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_version/))

```sh
use auxiliary/scanner/mysql/mysql_version
```

<!-- Info {{{-->
> [!info]-
>
> Enumerates the version of MySQL servers
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf > use auxiliary/scanner/mysql/mysql_version
> msf auxiliary(mysql_version) > show actions
>     ...actions...
> msf auxiliary(mysql_version) > set ACTION < action-name >
> msf auxiliary(mysql_version) > show options
>     ...show and set options...
> msf auxiliary(mysql_version) > run
> ```
<!-- }}} -->

MySQL Authentication Bypass Password Dump
([mysql_authbypass_hashdump](https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_authbypass_hashdump/))

```sh
msf> use auxiliary/scanner/mysql/mysql_authbypass_hashdump
```

<!-- Info {{{-->
> [!info]-
>
> This module exploits a password bypass vulnerability in MySQL
> in order to extract the usernames and encrypted password hashes
> from a MySQL server
>
> Impacts MySQL versions:
> - `5.1.x` before `5.1.63`
> - `5.5.x` before `5.5.24`
> - `5.6.x` before `5.6.6`
>
> And MariaDB versions:
> - `5.1.x` before `5.1.62`
> - `5.2.x` before `5.2.12`
> - `5.3.x` before `5.3.6`
> - `5.5.x` before `5.5.23`
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf > use auxiliary/scanner/mysql/mysql_authbypass_hashdump
> msf auxiliary(mysql_authbypass_hashdump) > show actions
>     ...actions...
> msf auxiliary(mysql_authbypass_hashdump) > set ACTION < action-name >
> msf auxiliary(mysql_authbypass_hashdump) > show options
>     ...show and set options...
> msf auxiliary(mysql_authbypass_hashdump) > run
> ```
<!-- }}} -->

MYSQL Password Hashdump
([mysql_hashdump](https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_hashdump/))

```sh
msf> use auxiliary/scanner/mysql/mysql_hashdump
```

<!-- Info {{{-->
> [!info]-
>
> Exploit a password bypass vulnerability to extract usernames
> and encrypted password hashes
>
> Impacts MySQL versions:
>
> - `5.1.x` before `5.1.63`
> - `5.5.x` before `5.5.24`
> - `5.6.x` before `5.6.6`
>
> And MariaDB versions:
>
> - `5.1.x` before `5.1.62`
> - `5.2.x` before `5.2.12`
> - `5.3.x` before `5.3.6`
> - `5.5.x` before `5.5.23`
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf > use auxiliary/scanner/mysql/mysql_hashdump
> msf auxiliary(mysql_hashdump) > show actions
>     ...actions...
> msf auxiliary(mysql_hashdump) > set ACTION < action-name >
> msf auxiliary(mysql_hashdump) > show options
>     ...show and set options...
> msf auxiliary(mysql_hashdump) > run
> ```
<!-- }}} -->

MySQL Enumeration Module
([mysql_enum](https://www.rapid7.com/db/modules/auxiliary/admin/mysql/mysql_enum/))
(*needs credentials*)

```sh
msf> use auxiliary/admin/mysql/mysql_enum
```

<!-- Info {{{-->
> [!info]-
>
> This module allows for simple enumeration of MySQL Database Server
> **provided proper credentials** to connect remotely
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf > use auxiliary/admin/mysql/mysql_enum
> msf auxiliary(mysql_enum) > show actions
>     ...actions...
> msf auxiliary(mysql_enum) > set ACTION < action-name >
> msf auxiliary(mysql_enum) > show options
>     ...show and set options...
> msf auxiliary(mysql_enum) > run
> ```
<!-- }}} -->

MYSQL Schema Dump
([mysql_schemadump](https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_schemadump/))

```sh
msf> use auxiliary/scanner/mysql/mysql_schemadump
```

<!-- Info {{{-->
> [!info]-
>
> This module extracts the schema information from a MySQL DB server
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf > use auxiliary/scanner/mysql/mysql_schemadump
> msf auxiliary(mysql_schemadump) > show actions
>     ...actions...
> msf auxiliary(mysql_schemadump) > set ACTION < action-name >
> msf auxiliary(mysql_schemadump) > show options
>     ...show and set options...
> msf auxiliary(mysql_schemadump) > run
> ```
<!-- }}} -->

Oracle MySQL for Microsoft Windows FILE Privilege Abuse
([mysql_start_up](https://www.rapid7.com/db/modules/exploit/windows/mysql/mysql_start_up/))

```sh
msf> use exploit/windows/mysql/mysql_start_up
```

<!-- Info {{{-->
> [!info]-
>
> This module abuses the `FILE` privilege to write a payload
> to Microsoft's All Users Start Up directory
> which will execute every time a user logs in
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf > use exploit/windows/mysql/mysql_start_up
> msf exploit(mysql_start_up) > show targets
>     ...targets...
> msf exploit(mysql_start_up) > set TARGET < target-id >
> msf exploit(mysql_start_up) > show options
>     ...show and set options...
> msf exploit(mysql_start_up) > exploit
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Banner Grabbing {{{-->
### Banner Grabbing

Banner grabbing with [[Nmap]]

```sh
nmap -sV -p 3306 <target> -oA mysql-banner
```

Banner grabbing with [[netcat]]

```sh
nc -vn <target> 3306
```

Banner grabbing with [[Telnet/General|Telnet]]

```sh
telnet <target> 3306
```

<!-- }}} -->

___

<!-- }}} -->

<!-- Database Enumeration {{{-->
## Database Enumeration

The most important databases on a MySQL server are

- **System Schema** (`sys`)
- **Information Schema** (`information_schema`)

<!-- Example {{{-->
> [!example]-
>
>
> 1. Select `sys` database
>
> ```sh
> mysql> use sys;
> ```
>
> 2. Show database tables
>
> ```sh
> mysql> show tables;
> ```
> ```sh
> +-----------------------------------------------+
> | Tables_in_sys                                 |
> +-----------------------------------------------+
> | host_summary                                  |
> | host_summary_by_file_io                       |
> | host_summary_by_file_io_type                  |
> | host_summary_by_stages                        |
> | host_summary_by_statement_latency             |
> | host_summary_by_statement_type                |
> | innodb_buffer_stats_by_schema                 |
> | innodb_buffer_stats_by_table                  |
> | innodb_lock_waits                             |
> | io_by_thread_by_latency                       |
> ...SNIP...
> | x$waits_global_by_latency                     |
> +-----------------------------------------------+
> ```
>
> 3. Display row values from a table
>
> ```sh
> mysql> select host, unique_users from host_summary;
> ```
> ```sh
> +-------------+--------------+
> | host        | unique_users |
> +-------------+--------------+
> | 10.129.14.1 |            1 |
> | localhost   |            2 |
> +-------------+--------------+
> 2 rows in set (0,01 sec)
> ```
<!-- }}} -->

<!-- Information Schema {{{-->
### Information Schema

Information schema (`information_schema`) stores metadata mainly retrieved from
the `system_schema` database, such as

- Databases and tables (`SCHEMATA`, `TABLES`, `COLUMNS`)
- Constraints and indexes (`KEY_COLUMN_USAGE`, `STATISTICS`)
- Privileges (`USER_PRIVILEGES`, `TABLE_PRIVILEGES`)
- Views, triggers, routines, and more

<!-- Example {{{-->
> [!example]-
>
> List all tables in a specific database
>
> ```sql
> SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'my_database';
> ```
<!-- }}} -->

<!-- }}} -->

<!-- System Schema {{{-->
### System Schema

[System Schema](https://dev.mysql.com/doc/refman/8.0/en/system-schema.html)
(`sys`) is MySQL’s admin helper layer, and is a curated set of views, functions,
and procedures built on top of `performance_schema` and `information_schema`,
containing

- Summaries of expensive queries
- I/O statistics per table or schema
- Wait events and latency breakdowns
- User-level activity and resource usage

<!-- Example {{{-->
> [!example]-
>
> See top 10 most expensive SQL statements
>
> ```sql
> SELECT * FROM sys.statement_analysis ORDER BY total_latency DESC LIMIT 10;
> ```
>
> See which tables are being hit the most
>
> ```sql
> SELECT * FROM sys.schema_table_statistics ORDER BY rows_fetched DESC LIMIT 10;
> ```
<!-- }}} -->

<!-- }}} -->

___

<!-- }}} -->

<!-- Permission Enumeration {{{-->
## Permission Enumeration

Enumerate [MySQL Permissions](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-mysql.html#mysql-permissions-enumeration):

1. **[[Enumeration#Privilege Discovery|Privilege Discovery]]** &
   **[[Enumeration#Account Enumeration|Account Enumeration]]**:
   `SHOW GRANTS` + `mysql.user` queries
2. **[[Enumeration#High-risk Privilege Check|Prioritization]]**:
   Pivot to `FILE`/`SUPER` owners
3. **[[Enumeration#Exploitation Checks|Exploitation Checks]]**:
   Inspect functions/plugins

### Privilege Discovery

[SHOW GRANTS](https://dev.mysql.com/doc/refman/8.4/en/show-grants.html)
displays the privileges and roles assigned to a MySQL user account or role

<!-- Example {{{-->
> [!example]-
>
> Display the privileges of the current user
>
> ```sql
> SHOW GRANTS;
> ```
>
> > [!info]-
> >
> > Quick self-audit on privileges
>
> Display the privileges of a specified user
>
> ```sql
> SHOW GRANTS [FOR user_or_role];
> ```
>
> > [!info]-
> >
> > Privilege escalation check
> > (e.g., `ALL PRIVILEGES`, `SUPER`, `FILE`, etc.)
>
> Display the privileges of a specified user on a specified host
>
> ```sql
> SHOW GRANTS FOR 'root'@'localhost';
> ```
>
> > [!info]-
> >
> > Confirm `root`'s power level, detect if `root` is misconfigured
> > (e.g., *limited privileges*, *wrong host-binding*)
>
> Display the privileges of an account executing the query
>
>
> ```sql
> SHOW GRANTS FOR CURRENT_USER();
> ```
>
> > [!info]-
> >
> > Reveal effective privileges, accounting for
> > authentication mappings or proxying
<!-- }}} -->

### Account Enumeration

Full dump of user accounts, privileges, and password hashes

<!-- Example {{{-->
> [!example]-
>
> Lists every MySQL user account, their authentication plugin, password hash,
> and all individual privilege columns (like `Select_priv`, `Insert_priv`, etc.)
>
> ```sql
> SELECT * FROM mysql.user;
> ```
>
> List the `root` account's authentication plugin, password hash, and privilege
> columns
>
> ```sql
> SELECT * FROM mysql.user WHERE user='root';
> ```
>
> > [!warning]
> >
> > This is a bad practice
> >
> > ```sh
> > `root`@`%`
> > ```
>
<!-- }}} -->

### High-risk Privilege Check

Find users with `FILE` and `SUPER` privileges

<!-- Example {{{-->
> [!example]-
>
> List all users with `FILE` privileges
>
> ```sql
> SELECT user,file_priv FROM mysql.user WHERE file_priv='Y';
> ```
>
> > [!info]-
> >
> > `FILE` allows reading and writing files on the server host —
> > potentially leading to privilege escalation via local file access
>
>
> List all users with `SUPER` privileges
>
> ```sql
> SELECT user,Super_priv FROM mysql.user WHERE Super_priv='Y';
> ```
>
> > [!info]-
> >
> > **: `SUPER` allows global operations
> > (e.g., *killing threads*, *changing replication*,
> > *modifying global variables*)
<!-- }}} -->

### Exploitation Checks

Find user-defined functions ([UDFs](https://en.wikipedia.org/wiki/User-defined_function))
— potentially leading to code execution backdoors
if loaded maliciously

<!-- Example {{{-->
> [!example]-
>
> List all user-defined functions across databases/schemas
>
> ```sql
> SELECT routine_name FROM information_schema.routines WHERE routine_type = 'FUNCTION';
> ```
>
> List all user-defined functions across databases/schemas
> (excludes system functions from the `sys` schema)
>
> ```sql
> SELECT routine_name FROM information_schema.routines WHERE routine_type = 'FUNCTION' AND routine_schema!='sys';
> ```
>
> > [!info]
> >
> > Both queries read rows from `information_schema.routines` and return the
> > `routine_name` for rows whose `routine_type` is `FUNCTION`
>
> > [!warning]
> >
> > User-defined functions can contain SQL logic that manipulates data, but they
> > can also be UDF wrappers (native code) that call OS-level APIs
>
> > [!tip]
> >
> > Check `DEFINER` + `SECURITY_TYPE`: a function defined by `root` with
> > `DEFINER` semantics is especially dangerous
<!-- }}} -->

___

<!-- }}} -->
