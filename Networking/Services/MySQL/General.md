---
id: General
aliases: []
tags:
  - Networking/Services/MySQL/General
port:
  - 3306
---

# MySQL

[MySQL](https://en.wikipedia.org/wiki/MySQL) is an open-source SQL relational
database management system developed by [Oracle](https://www.mysql.com/).

**MySQL** works according to the client-server principle and consist of a
[[General#MySQL Database|MySQL Server]] and
[[General#MySQL Clients|MySQL Client(s)]].

The **MySQL** database is controlled using the
[SQL database language](https://www.w3schools.com/sql/sql_intro.asp),
and is often stored in a single file with the file extension `.sql`.

<!-- MySQL Clients {{{-->
## MySQL Clients

The **MySQL Clients** can retrieve and edit the data using structured queries to
the database engine.

**MySQL** is suitable for managing many different databases to which
[[General#MySQL Clients|MySQL Clients]] can send multiple queries
simultaneously.
<!-- }}} -->

<!-- MySQL Database {{{-->
## MySQL Database

**MySQL** is suited for applications (e.g., dynamic websites), where efficient
syntax and high response speed are essential.

**MySQL databases** often exist in the following combinations:

- [LAMP](https://en.wikipedia.org/wiki/LAMP_(software_bundle)): Linux OS,
  Apache, MySQL, PHP
- [LEMP](https://lemp.io/): Linux OS, Nginx, MySQL, PHP
<!-- }}} -->

<!-- MySQL Commands {{{-->
## MySQL Commands

A [[General#MySQL Database|MySQL Database]] receives structured queries from
the client, parses them, optimizes the execution plan, and performs the
requested operations on the data.

The database engine returns the result — whether it is retrieved data,
confirmation of a change, or an error message — to the web application.

**MySQL commands** are grouped into categories based on their purpose:

- **Data definition** (**DDL**) — Creating or changing the structure of the
  database
  (e.g., `CREATE`, `ALTER` or `DROP` the tables, views, indexes, schemas, etc.)

- **Data manipulation** (**DML**) — working with the contents of the tables
  (e.g., `SELECT`, `INSERT`, `UPDATE`, `DELETE`)

- **Data control** (**DCL**) — managing access and permissions
  (e.g., `GRANT`, `REVOKE`)

- **Transaction control** (**TCL**) — ensuring data consistency and atomicity
  (e.g., `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `START TRANSACTION`)

<!-- Example {{{-->
> [!example]-
>
> | Command                                              | Description                |
> | ---------------------------------------------------- | -------------------------- |
> | `mysql -u <user> -p<password> -h <IP address>`       | Connect to the MySQL server | There should not be a space between the '-p' flag, and the password.
> | `show databases;`                                    | Show all databases                   |
> | `use <database>;`                                    | Select one of the existing databases |
> | `show tables;`                                       | Show all available tables in the selected database |
> | `show columns from <table>;`                         | Show all columns in the selected table |
> | `select * from <table>;`                             | Show everything in the desired table |
> | `select * from <table> where <column> = "<string>";` | Search for needed string in the desired table |
<!-- }}} -->

<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

<!-- Default Configuration {{{-->
### Default Configuration

The **Default Configuration** is located at `/etc/mysql/mysql.conf.d/mysqld.cnf`

The [MySQL reference](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html)
contains the options that can be made on the server configuration

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
> ```
> ```sh
> [client]
> port            = 3306
> socket          = /var/run/mysqld/mysqld.sock
>
> [mysqld_safe]
> pid-file        = /var/run/mysqld/mysqld.pid
> socket          = /var/run/mysqld/mysqld.sock
> nice            = 0
>
> [mysqld]
> skip-host-cache
> skip-name-resolve
> user            = mysql
> pid-file        = /var/run/mysqld/mysqld.pid
> socket          = /var/run/mysqld/mysqld.sock
> port            = 3306
> basedir         = /usr
> datadir         = /var/lib/mysql
> tmpdir          = /tmp
> lc-messages-dir = /usr/share/mysql
> explicit_defaults_for_timestamp
>
> symbolic-links = 0
>
> !includedir /etc/mysql/conf.d/
> ```
<!-- }}} -->
<!-- }}} -->

<!-- Dangerous Settings {{{-->
### Dangerous Settings

The settings `user`, `password`, and `admin_address` are security-relevant
as they may expose sensitive authentication and network details directly in
plain-text configuration files.

The `debug` and `sql_warnings` settings provide verbose information output in
case of errors, which are essential for the administrator but should not be seen
by others.

> [!danger]-
>
> | Settings           | Description
> | ------------------ | ------------------------------------------------------ |
> | `user`             | Sets which user the MySQL service will run as          |
> | `password`         | Sets the password for the MySQL user                   |
> | `admin_address`    | The IP address on which to listen for TCP/IP connections on the administrative network interface |
> | `debug`            | Indicates the current debugging settings |
> | `sql_warnings`     | Controls whether single-row `INSERT` statements produce an information string if warnings occur |
> | `secure_file_priv` | Used to limit the effect of data import and export operations |

> [!warning]
>
> Often, the **rights for the configuration file** of the **MySQL server** are
> not assigned correctly.
>
> If an attacker can read files or gain shell access, they may retrieve the file
> containing the MySQL username and password.
<!-- }}} -->
<!-- }}} -->
