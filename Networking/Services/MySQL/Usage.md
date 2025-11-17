---
id: Usage
aliases: []
tags:
  - Networking/Services/MySQL/Usage
---

# Usage

___

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
mysql -u <user> -p<password> -h <target_ip>
```

```sh
mysql -h <hostname> -p<password> -u root@localhost
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

> [!tip]- SSL/TLS ERROR 2026 (HY000)
>
> MySQL client may refuse to trust
> the SSL self-signed certificate
>
> ```
> ERROR 2026 (HY000): TLS/SSL error: self-signed certificate in certificate chain
> ```
>
> - below MySQL 5.7 / MariaDB 10.2
>
> ```sh
> --ssl=0
> ```
> ```sh
> --skip-ssl
> ```
> ```sh
> --ssl --ssl-verify-server-cert=0 
> ```
>
> - above MySQL 5.7 / MariaDB 10.2
>
> ```sh
> --ssl-mode=DISABLED
> ```
> ```sh
> --ssl-mode=PREFERRED
> ```

<!-- }}} -->

___
<!-- }}} -->

<!-- Databases {{{-->
## Databases

Databate operations — Enumerate databases to identify high-value targets

<!-- Discover {{{-->
### Discover

List all databases

```sql
SHOW DATABASES;
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
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
> ```
<!-- }}} -->

List all database information

```sql
SELECT * FROM INFORMATION_SCHEMA.SCHEMATA;
```

<!-- }}} -->

<!-- Select {{{-->
### Select

Select a database

```sql
USE <database_name>;
```

> [!example]-
>
> ```sql
> USE my_database;
> ```

<!-- }}} -->

<!-- Current {{{-->
### Current

Show current database

```sql
SELECT DATABASE();
```

Show current database information

```sql
SELECT SCHEMA_NAME, CREATE_TIME FROM INFORMATION_SCHEMA.SCHEMATA;
```

<!-- }}} -->

<!-- Create {{{-->
### Create

Create a database

```sql
CREATE DATABASE <name>;
```

> [!example]-
>
> ```sql
> CREATE DATABASE my_database;
> ```

<!-- }}} -->

<!-- Delete {{{-->
### Delete

Delete a database

```sql
DROP DATABASE <name>;
```

> [!example]-
>
> ```sql
> DROP DATABASE my_database;
> ```

<!-- }}} -->

___

<!-- }}} -->

<!-- Table {{{-->
## Table

Table operations —  Extract table and column information from databases

<!-- Discover {{{-->
### Discover

List tables in current database

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
SELECT column_name, data_type FROM information_schema.COLUMNS WHERE table_name='<table>';
```

> [!example]-
>
> ```sql
> SELECT column_name, data_type FROM information_schema.COLUMNS WHERE table_name='users';
> ```

Search for a specific column in a table

```sql
SELECT table_name, column_name
FROM information_schema.columns
WHERE column_name LIKE '%search_term%'
```

> [!example]-
>
> ```sql
> SELECT table_name, column_name
> FROM information_schema.columns
> WHERE column_name LIKE '%password%'
> ```

<!-- }}} -->

<!-- Modify {{{-->
### Modify

Modify tables

<!-- Create {{{-->
#### Create

Create a table with header

```sql
CREATE TABLE <table_name> (
    <column_1> INT AUTO_INCREMENT PRIMARY KEY,
    <column_2> VARCHAR(100),
    <column_3> DATETIME
);
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> CREATE TABLE users (
>     id INT AUTO_INCREMENT PRIMARY KEY,
>     name VARCHAR(100),
>     email DATETIME
> );
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Delete {{{-->
#### Delete

Delete a table

```sql
DROP TABLE <table_name>;
```

> [!example]-
>
> ```sql
> DROP TABLE users;
> ```

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Data {{{-->
## Data

Table data operations

<!-- View {{{-->
### View

View table data

```sql
SELECT * FROM table_name;
```

Limit table data to `10` rows

```sql
SELECT * FROM table_name LIMIT 10;
```
<!-- }}} -->

<!-- Filter {{{-->
### Filter

Filter table data

```sql
SELECT * FROM myTable WHERE id = 5;
```

```sql
SELECT * FROM myTable WHERE name = 'Alice';
```

Filter table data (*multiple*)

```sql
SELECT * FROM myTable WHERE age > 30 AND city = 'London';
```
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
