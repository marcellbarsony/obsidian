---
id: Enumeration
aliases: []
tags:
  - Networking/Services/MySQL/Enumeration
---

# Enumeration

## Configuration File

Often, the rights for the [[General#Configuration|configuration file]] of the
[[General#MySQL Database|MySQL databases]] are not assigned correctly.

> [!tip]
>
> If an attacker can read files or gain shell access, they may retrieve the file
> containing the MySQL username and password

<!-- Scanning MySQL Server {{{-->
## Scanning MySQL Server

[[General#MySQL Database|MySQL Databases]] can be enumerated using [[Nmap Scripting Engine|Nmap NSE]]
scripts

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
> ```
>
> > [!info]-
> >
> > - `--script mysql*`: Run every NSE script related to MySQL
>
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

> [!warning]
>
> The **scan results should be confirmed manually**
> as some of the information might turn out to be **false-positive**

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
> ```sh
> mysql> use sys;
> mysql> show tables;
>
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
>
> mysql> select host, unique_users from host_summary;
>
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
> ```sql
> -- List all tables in a specific database
> SELECT TABLE_NAME
> FROM information_schema.TABLES
> WHERE TABLE_SCHEMA = 'my_database';
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
> ```sql
> -- See top 10 most expensive SQL statements
> SELECT * FROM sys.statement_analysis ORDER BY total_latency DESC LIMIT 10;
> ```
>
> ```sql
> 
> -- See which tables are being hit the most
> SELECT * FROM sys.schema_table_statistics ORDER BY rows_fetched DESC LIMIT 10;
> ```
<!-- }}} -->

<!-- }}} -->

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
> **Purpose**: Quick self-audit on privileges
>
> ```sql
> SHOW GRANTS;
> ```
>
> Display the privileges of a specified user
>
> **Purpose**: Privilege escalation check
> (e.g., `ALL PRIVILEGES`, `SUPER`, `FILE`, etc.)
>
> ```sql
> SHOW GRANTS [FOR user_or_role];
> ```
>
> Display the privileges of a specified user on a specified host
>
> **Purpose**: Confirm `root`'s power level, detect if `root` is misconfigured
> (e.g., *limited privileges*, *wrong host-binding*)
>
> ```sql
> SHOW GRANTS FOR 'root'@'localhost';
> ```
>
> Display the privileges of an account executing the query
>
> **Purpose**: Reveal effective privileges, accounting for authentication
> mappings or proxying
>
> ```sql
> SHOW GRANTS FOR CURRENT_USER();
> ```
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
> **Purpose**: `FILE` allows reading and writing files on the server host —
> potentially leading to privilege escalation via local file access
>
> ```sql
> SELECT user,file_priv FROM mysql.user WHERE file_priv='Y';
> ```
>
> List all users with `SUPER` privileges
>
> **Purpose**: `SUPER` allows global operations
> (e.g., *killing threads*, *changing replication*,
> *modifying global variables*)
>
> ```sql
> SELECT user,Super_priv FROM mysql.user WHERE Super_priv='Y';
> ```
<!-- }}} -->

### Exploitation Checks

Find user-defined functions (UDFs) — potentially leading to code execution
backdoors if loaded maliciously

<!-- Example {{{ -->
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
