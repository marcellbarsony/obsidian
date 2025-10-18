---
id: Usage
aliases: []
tags:
  - Networking/Services/MySQL/Usage
---

# Usage

<!-- Connect {{{-->
## Connect

Connect to a database (*remote or local*)

<!-- Local {{{-->
### Local

Connect to `root` without password

```sh
mysql -u root
```

Connect to `root` with password

```sh
mysql -u root -p
```

<!-- }}} -->

<!-- Remote {{{-->
### Remote

Connect to a remote MySQL server without password

```sh
mysql -h <hostname> -u root
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> mysql -u root -h 10.129.14.132
> ```
> ```sh
> ERROR 1045 (28000): Access denied for user 'root'@'10.129.14.1' (using password: NO)
> ```
<!-- }}} -->

Connect to a remote MySQL server with password

```sh
mysql -h <hostname> -pP4SSw0rd -u root@localhost
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> mysql -u root -pP4SSw0rd -h 10.129.14.128
> ```
> ```sh
> Welcome to the MariaDB monitor.  Commands end with ; or \g.
> Your MySQL connection id is 150165
> Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)
> Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
> Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
>
> MySQL [(none)]> show databases;
> +--------------------+
> | Database           |
> +--------------------+
> | information_schema |
> | mysql              |
> | performance_schema |
> | sys                |
> +--------------------+
> 4 rows in set (0.006 sec)
>
>
> MySQL [(none)]> select version();
> +-------------------------+
> | version()               |
> +-------------------------+
> | 8.0.27-0ubuntu0.20.04.1 |
> +-------------------------+
> 1 row in set (0.001 sec)
>
>
> MySQL [(none)]> use mysql;
> MySQL [mysql]> show tables;
> +------------------------------------------------------+
> | Tables_in_mysql                                      |
> +------------------------------------------------------+
> | columns_priv                                         |
> | component                                            |
> | db                                                   |
> | default_roles                                        |
> | engine_cost                                          |
> | func                                                 |
> | general_log                                          |
> | global_grants                                        |
> | gtid_executed                                        |
> | help_category                                        |
> | help_keyword                                         |
> | help_relation                                        |
> | help_topic                                           |
> | innodb_index_stats                                   |
> | innodb_table_stats                                   |
> | password_history                                     |
> ...SNIP...
> | user                                                 |
> +------------------------------------------------------+
> 37 rows in set (0.002 sec)
> ```
<!-- }}} -->

<!-- }}} -->

___

<!-- }}} -->

<!-- Version Info {{{-->
## Version Info

Show MySQL version

```sh
SELECT @@version;
```

```sh
SELECT VERSION();
```

Show server version

```sql
SELECT @@version_compile_os;
```

```sh
SELECT @@version_compile_machine;
```

```sh
SHOW VARIABLES LIKE "%version%";
```

___

<!-- }}} -->

## Configuration

Show important variables

```sh
SHOW VARIABLES;
```

> [!example]-
>
>
> ```sh
> SHOW VARIABLES LIKE 'secure_file_priv';  # File operations directory
> SHOW VARIABLES LIKE 'plugin_dir';        # Plugin directory
> SHOW VARIABLES LIKE 'datadir';           # Data directory
> SHOW VARIABLES LIKE 'basedir';           # Base directory
> ```

Check if `local_infile` enabled

```sh
SHOW VARIABLES LIKE 'local_infile';
```

Process list

```sh
SHOW PROCESSLIST;
```

<!-- User {{{-->
## User

Show current user

```sql
SELECT USER();
```

```sql
SELECT CURRENT_USER();
```

List MySQL users

```sql
SELECT user, host FROM mysql.user;
```

<!-- Privileges {{{-->
### Privileges

Show user privileges

```sql
SHOW GRANTS;
```

```sql
SHOW GRANTS FOR '<username>'@'<host>';
```

List users with `FILE` privilege

```sql
SELECT user, host FROM mysql.user WHERE File_priv = 'Y';
```

List users with `SUPER` privilege

```sql
SELECT user, host FROM mysql.user WHERE Super_priv = 'Y';
```

<!-- }}} -->

___

<!-- }}} -->

<!-- Databases {{{-->
## Databases

Database operations

<!-- Discover {{{-->
### Discover

Show all databases

```sql
SHOW DATABASES;
```

<!-- Example {{{-->
> [!example]-
>
>```sh
>MySQL [(none)]> show databases;
>+--------------------+
>| Database           |
>+--------------------+
>| information_schema |
>| mysql              |
>| performance_schema |
>| sys                |
>+--------------------+
>4 rows in set (0.006 sec)
>```
<!-- }}} -->

<!-- }}} -->

<!-- Select {{{-->
### Select

Select a database

```sql
USE my_database;
```

<!-- }}} -->

<!-- Show {{{-->
### Show

Show current database

```sql
SELECT DATABASE();
```

<!-- }}} -->

<!-- Create {{{-->
### Create

Create a database

```sql
CREATE DATABASE my_database;
```

<!-- }}} -->

<!-- Delete {{{-->
### Delete

Delete a database

```sql
DROP DATABASE my_database;
```

<!-- }}} -->

___

<!-- }}} -->

<!-- Table {{{-->
## Table

Table operations

<!-- Discover {{{-->
### Discover

Show tables in current database

```sql
SHOW TABLES;
```

```sql
SELECT table_name FROM information_schema.TABLES WHERE table_schema=DATABASE();
```

<!-- }}} -->

<!-- Structure {{{-->
### Structure

Show table structure
(e.g., *column names, data types, keys, default values, etc.*)

```sql
DESCRIBE table_name;
```

```sql
SHOW COLUMNS FROM table_name;
```

```sql
SELECT column_name, data_type FROM information_schema.COLUMNS WHERE table_name='<users>';
```

<!-- }}} -->

<!-- Data {{{-->
### Data

View table data

```sql
SELECT * FROM table_name;
```

Limit table data to `10` rows

```sql
SELECT * FROM table_name LIMIT 10;
```

<!-- }}} -->

<!-- Modify {{{-->
### Modify

Modify tables

<!-- Create {{{-->
#### Create

Create a table with header

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100)
);
```

<!-- }}} -->

<!-- Delete {{{-->
#### Delete

Delete a table

```sql
DROP TABLE users;
```

<!-- }}} -->

<!-- }}} -->

___

<!-- }}} -->

<!-- Record {{{-->
## Record

Modify **SQL records**

<!-- Insert {{{-->
### Insert

Insert a record

```sql
INSERT INTO users (name, email) VALUES ('Alice', 'alice@email.com');
```

<!-- }}} -->

<!-- Update {{{-->
### Update

Update a record

```sql
UPDATE users SET email = 'new@email.com' WHERE id = 1;
```

<!-- }}} -->

<!-- Delete {{{-->
### Delete

Delete a record

```sql
DELETE FROM users WHERE id = 1;
```

<!-- }}} -->

___

<!-- }}} -->
