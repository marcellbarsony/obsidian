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
mysql -u <user> -p<password> -h $target
```

```sh
mysql -u root@loaclhost -p<password> -h <hostname> -P <port>
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

<!-- Tip {{{-->
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

<!-- }}} -->

___
<!-- }}} -->

<!-- Database {{{-->
## Database

Databate operations — Enumerate databases to identify high-value targets

<!-- Tip {{{-->
> [!tip]
>
> Common [[Networking/Services/MySQL/General#MySQL Database|MySQL Databases]]
>
<!-- }}} -->

<!-- Discover {{{-->
### Discover

[SHOW](https://dev.mysql.com/doc/en/show-databases.html)
all databases

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

[SHOW](https://dev.mysql.com/doc/en/show-databases.html)
all database information

```sql
SELECT * FROM INFORMATION_SCHEMA.SCHEMATA;
```

<!-- }}} -->

<!-- Use {{{-->
### Use

[USE](https://dev.mysql.com/doc/en/use.html)
a database

```sql
USE database_name;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> USE my_database;
> ```
<!-- }}} -->

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

[CREATE](https://dev.mysql.com/doc/en/create-database.html)
a database

```sql
CREATE DATABASE database_name;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> CREATE DATABASE my_database;
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Delete {{{-->
### Delete

[DROP](https://dev.mysql.com/doc/en/drop-database.html)
a database

```sql
DROP DATABASE database_name;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> DROP DATABASE my_database;
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Table {{{-->
## Table

Table operations — Extract table and column information from databases

<!-- Discover {{{-->
### Discover

[SHOW](https://dev.mysql.com/doc/en/show-tables.html)
tables in current database

```sql
SHOW TABLES;
```

```sql
SELECT table_name FROM information_schema.TABLES WHERE table_schema=DATABASE();
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> mysql> SHOW TABLES;
> ```
> ```sh
> +----------------------------+
> | Tables_in_htbusers         |
> +----------------------------+
> | actions                    |
> | permissions                |
> | permissions_roles          |
> | permissions_users          |
> | roles                      |
> | roles_users                |
> | settings                   |
> | users                      |
> +----------------------------+
> 8 rows in set (0.00 sec)
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- Structure {{{-->
### Structure

[DESCRIBE](https://dev.mysql.com/doc/en/describe.html)
table structure
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

<!-- Alter {{{-->
#### Alter

[ALTER](https://dev.mysql.com/doc/en/alter-table.html)
table name or field

```sql
ALTER TABLE table_name ADD column_name INT;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> mysql> ALTER TABLE logins ADD newColumn INT;
> ```
> ```sh
> Query OK, 0 rows affected (0.01 sec)
> ```
>
<!-- }}} -->

Rename a column

```sql
ALTER TABLE table_name RENAME COLUMN column_old TO column_new;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> mysql> ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
> ```
> ```sh
> Query OK, 0 rows affected (0.01 sec)
> ```
>
<!-- }}} -->

Change a column's datatype

```sql
ALTER TABLE table_name MODIFY column_name DATE;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> mysql> ALTER TABLE logins MODIFY newerColumn DATE;
> ```
> ```sh
> Query OK, 0 rows affected (0.01 sec)
> ```
>
<!-- }}} -->

Delete a column

```sql
ALTER TABLE table_name DROP column_name;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> mysql> ALTER TABLE logins DROP newerColumn;
> ```
> ```sh
> Query OK, 0 rows affected (0.01 sec)
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- Create {{{-->
#### Create

[CREATE](https://dev.mysql.com/doc/en/create-table.html)
Create a table with header

```sql
CREATE TABLE table_name (
    column_1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    column_2 VARCHAR(100) UNIQUE NOT NULL,
    column_3 DATETIME
);
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> CREATE TABLE users (
>     id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
>     name VARCHAR(100) UNIQUE NOT NULL,
>     email DATETIME
> );
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Delete {{{-->
#### Delete

[DROP](https://dev.mysql.com/doc/en/drop-table.html)
(*delete*) a table

```sql
DROP TABLE table_name;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> DROP TABLE users;
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Record {{{-->
## Record

Modify **SQL records**

<!-- Delete {{{-->
### Delete

[DELETE](https://dev.mysql.com/doc/en/delete.html)
a record

```sql
DELETE FROM users WHERE id = 1;
```

<!-- }}} -->

<!-- Insert {{{-->
### Insert

[INSERT](https://dev.mysql.com/doc/en/insert.html)
a single record

```sql
INSERT INTO table_name VALUES (1, 'value_1', 'value_2');
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> INSERT INTO logins VALUES (1, 'admin', 'p@ssw0rd', '2020-07-02');
> ```
<!-- }}} -->

[INSERT](https://dev.mysql.com/doc/en/insert.html)
mulpitle records

```sql
INSERT INTO table_name (column_1, column_2) VALUES ('value_1', 'value_2');
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> INSERT INTO users (name, email) VALUES ('Alice', 'alice@email.com');
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Select {{{-->
### Select

[SELECT](https://dev.mysql.com/doc/en/select.html)
everything

```sql
SELECT * FROM table_name;
```

[SELECT](https://dev.mysql.com/doc/en/select.html)
specific columns

```sql
SELECT column_1, column_2 FROM table;
```

<!-- }}} -->

<!-- Update {{{-->
### Update

[UPDATE](https://dev.mysql.com/doc/en/update.html)
a record

```sql
UPDATE table_name SET record = 'value' WHERE id = 1;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> UPDATE users SET email = 'new@email.com' WHERE id = 1;
> ```
<!-- }}} -->


<!-- }}} -->

___

<!-- }}} -->

<!-- Data {{{-->
## Data

Table data operations and
[Pattern Matching](https://dev.mysql.com/doc/en/pattern-matching.html)

<!-- Filter {{{-->
### Filter

[WHERE](https://dev.mysql.com/doc/en/where-optimization.html)

Filter table data

```sql
SELECT * FROM table_name WHERE column_name = value;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> SELECT * FROM table_name WHERE id = 5;
> ```
>
> ```sql
> SELECT * FROM table_name WHERE name = 'Alice';
> ```
>
<!-- }}} -->

Filter table data (*multiple*)

```sql
SELECT * FROM table_name WHERE column_1 = value AND column_2 > value;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> SELECT * FROM table_name WHERE age > 30 AND city = 'London';
> ```
>
<!-- }}} -->

[LIKE](https://dev.mysql.com/doc/en/pattern-matching.html)

```sql
SELECT * FROM table_name WHERE column_name LIKE condition;
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> mysql> SELECT * FROM logins WHERE username LIKE 'admin%';
> ```
> ```sh
> +----+---------------+------------+---------------------+
> | id | username      | password   | date_of_joining     |
> +----+---------------+------------+---------------------+
> |  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
> |  4 | administrator | adm1n_p@ss | 2020-07-02 15:19:02 |
> +----+---------------+------------+---------------------+
> 2 rows in set (0.00 sec)
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- Limit {{{-->
### Limit

[LIMIT](https://dev.mysql.com/doc/en/select.html)
table data to `10` rows

```sql
SELECT * FROM table_name LIMIT 10;
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> SELECT * FROM logins LIMIT 2;
> ```
> ```sh
> +----+---------------+------------+---------------------+
> | id | username      | password   | date_of_joining     |
> +----+---------------+------------+---------------------+
> |  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
> |  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
> +----+---------------+------------+---------------------+
> 2 rows in set (0.00 sec)
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- Sort {{{-->
### Sort

[ORDER BY](https://dev.mysql.com/doc/en/order-by-optimization.html)

```sql
SELECT * FROM table_name ORDER BY column_name;
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> mysql> SELECT * FROM logins ORDER BY password;
> ```
> ```sh
> +----+---------------+------------+---------------------+
> | id | username      | password   | date_of_joining     |
> +----+---------------+------------+---------------------+
> |  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
> |  3 | john          | john123!   | 2020-07-02 11:47:16 |
> |  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
> |  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
> +----+---------------+------------+---------------------+
> 4 rows in set (0.00 sec)
> ```
>
<!-- }}} -->

Order by `ASC` or `DSC`

```sql
SELECT * FROM table_name ORDER BY column_name DESC;
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> mysql> SELECT * FROM logins ORDER BY password;
> ```
> ```sh
> +----+---------------+------------+---------------------+
> | id | username      | password   | date_of_joining     |
> +----+---------------+------------+---------------------+
> |  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
> |  3 | john          | john123!   | 2020-07-02 11:47:16 |
> |  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
> |  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
> +----+---------------+------------+---------------------+
> 4 rows in set (0.00 sec)
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- View {{{-->
### View

View table data

```sql
SELECT * FROM table_name;
```

<!-- }}} -->

___
<!-- }}} -->
