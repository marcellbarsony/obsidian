---
id: Usage
aliases: []
tags:
  - Networking/Services/MSSQL/Usage
---

# Usage

___

<!-- Connect {{{-->
## Connect

<!-- Mssqlclient {{{-->
### Mssqlclient

[[Impacket]] - [mssqlclient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) —
Connect remotely to the MSSQL server using Transact-SQL
(*[T-SQL](https://learn.microsoft.com/en-us/sql/t-sql/language-reference?view=sql-server-ver17)*)

Connect to a MSSQL server

```sh
impacket-mssqlclient $target/<user>@<target_ip> -windows-auth
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> impacket-mssqlclient ARCHETYPE/Administrator@10.129.201.248 -windows-auth
> ```
> ```sh
> Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
>
> Password:
> [*] Encryption required, switching to TLS
> [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
> [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
> [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
> [*] INFO(SQL-01): Line 1: Changed database context to 'master'.
> [*] INFO(SQL-01): Line 1: Changed language setting to us_english.
> [*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
> [!] Press help for extra shell commands
> ```
>
> ```sql
> SQL> select name from sys.databases
> ```
> ```sh
> name
>
> --------------------------------------------------------------------------------------
>
> master
>
> tempdb
>
> model
>
> msdb
>
> Transactions
> ```
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> Valid credentials required
<!-- }}} -->

Windows authentication

```sh
impacket-mssqlclient <DOMAIN>/<user>:<password>@$target
```

SQL authentication

```sh
impacket-mssqlclient sa:<password>@$target -windows-auth
```

Connect to a specific database

```sh
impacket-mssqlclient <user>:<password>@$target -db master
```

Connect with hash (*Pass-the-Hash*)

```sh
impacket-mssqlclient <user>@$target -hashes :NTHASH
```

<!-- }}} -->

<!-- SQLCMD {{{-->
### SQLCMD

[sqlcmd](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-use-utility) —
the [sqlcmd utility](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver17)
allows enter Transact-SQL statements, system procedures,
and script files through a variety of available modes

```sh
sqlcmd -S $target -U <username> -P <password>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
> ```
<!-- }}} -->

<!-- }}} -->

<!-- SQSH {{{-->
### SQSH


[sqsh](https://en.wikipedia.org/wiki/Sqsh) —
Connect to a MSSQL server over the
[TDS protocol](https://en.wikipedia.org/wiki/Tabular_Data_Stream)

```sh
sqsh -S $target -U <username> -P <password>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sqsh -S 10.129.20.13 -U username -P Password123
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Database {{{-->
## Databases

Databate operations — Enumerate databases to identify high-value targets

> [!tip]
>
> Common [[Networking/Services/MSSQL/General#Database|System Databases]]

<!-- Discover {{{-->
### Discover

List all databases

```sql
SELECT name FROM sys.databases;
```

```sql
SELECT name FROM master.dbo.sysdatabases;
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> SQL (ILF-SQL-01\backdoor  dbo@master)> SELECT name FROM sys.databases;
> name
> ---------
> master
>
> tempdb
>
> model
>
> msdb
>
> Employees 4 rows in set (0.006 sec)
> ```
<!-- }}} -->

List all database information
(*e.g., size, owner, creation date, file location, status, flags, etc.*)

```sql
EXEC sp_helpdb;
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
> ```sql
> ENVCHANGE(DATABASE): Old Value: master, New Value: Employees
> INFO(ILF-SQL-01): Line 1: Changed database context to 'Employees'.
> ```

<!-- }}} -->

<!-- Current {{{-->
### Current

Show current database

```sql
SELECT DB_NAME();
```

Show current database information

```sql
SELECT name, database_id, create_date FROM sys.databases;
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
SELECT table_name FROM information_schema.tables;
```

```sql
SELECT name FROM sys.tables;
```

<!-- }}} -->

<!-- Structure {{{-->
### Structure

Show table structure
(e.g., *column names, data types, keys, default values, etc.*)

```sql
SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '<table>';
```

> [!example]-
>
> ```sql
> SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users';
> ```

Search for a specific column in a table

```sql
SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '<column_name>';
```

> [!example]-
>
> ```sql
> SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%password%';
> ```

Count rows in tables

```sql
SELECT t.name, p.rows FROM sys.tables t INNER JOIN sys.partitions p ON t.object_id = p.object_id WHERE p.index_id < 2;
```

<!-- }}} -->

<!-- Modify {{{-->
### Modify

Modify tables

<!-- Create {{{-->
#### Create

Create a table with header

```sql
CREATE TABLE <table_name> ( <column_1> INT PRIMARY KEY, <column_2> NVARCHAR(50), <column_3> DATETIME );
```

> [!example]-
>
> ```sql
> CREATE TABLE users (
>     id INT AUTO_INCREMENT PRIMARY KEY,
>     name NVARCHAR(100),
>     email DATETIME
> );
> ```

<!-- }}} -->

<!-- Delete {{{-->
#### Delete

Delete a table

```sql
DROP TABLE <table>;
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> DROP TABLE Employees;
> ```
<!-- }}} -->

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
