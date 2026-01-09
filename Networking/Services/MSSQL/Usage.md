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
impacket-mssqlclient <DOMAIN>/<user>@$target -windows-auth
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
The [sqlcmd utility](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver17)
allows enter Transact-SQL statements, system procedures,
and script files through a variety of available modes

<!-- Install {{{-->
#### Install

[Download and install the sqlcmd utility](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-download-install?view=sql-server-ver17&tabs=linux)

1. Import the public repository GPG keys

```sh
curl https://packages.microsoft.com/keys/microsoft.asc | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc
```

2. Install common software repositories

```sh
sudo apt install software-properties-common
```

3. Add the Microsoft repository
(*`ubuntu/20.04` segment might be `debian/11`, `ubuntu/20.04`,
or `ubuntu/22.04`*)

```sh
sudo add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/20.04/prod.list)"
```

4. Install sqlcmd with apt

```sh
sudo apt install sqlcmd
```

<!-- }}} -->

<!-- Connect {{{-->
#### Connect

Connect

```sh
sqlcmd -S $target -U <username>
```

```sh
sqlcmd -S $target -U <username> -P <password>
```

```sh
sqlcmd -S $target -U <username> -P <password> -y 30 -Y 30
```

<!-- Info {{{-->
> [!info]-
>
> - `-y`: [variable_length_type_display_width](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver17&tabs=go%2Cwindows-support&pivots=cs1-bash#-y-variable_length_type_display_width)
> - `-Y`: [fixed_length_type_display_width](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver17&tabs=go%2Cwindows-support&pivots=cs1-bash#-y-fixed_length_type_display_width)
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
> ```
> ```sh
> 1>
> ```
<!-- }}} -->

<!-- Tip {{{-->
> [!tip]
>
> `sqlcmd` requires to issue `GO` after the query
>
> ```sh
> SELECT name FROM master.dbo.sysdatabases
> ```
> ```sh
> GO
> ```
>
> <!-- Example {{{-->
> > [!example]-
> >
> > ```sh
> > 1> SELECT name FROM master.dbo.sysdatabases
> > ```
> > ```sh
> > 2> GO
> > ```
> >
> > ```sh
> > name
> > --------------------------------------------------
> > master
> > tempdb
> > model
> > msdb
> > htbusers
> > ```
> <!-- }}} -->
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- SQSH {{{-->
### SQSH

[sqsh](https://en.wikipedia.org/wiki/Sqsh) —
Connect to a MSSQL server over the
[TDS protocol](https://en.wikipedia.org/wiki/Tabular_Data_Stream)

SQL Authentication

```sh
sqsh -S $target -U <username> -P <password> -h
```

<!-- Info {{{-->
> [!info]-
>
> - `-U`: Username
> - `-P`: Password
> - `-h`: Disable headers and footers
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sqsh -S 10.129.20.13 -U username -P Password123
> ```
<!-- }}} -->

Windows Authentication

```sh
sqsh -S $target -U .\\<username> -P <password> -h
```

<!-- Info {{{-->
> [!info]-
>
> - `-U`: Username
> - `-P`: Password
> - `-h`: Disable headers and footers
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
> ```
> ```sh
> sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
> Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
> This is free software with ABSOLUTELY NO WARRANTY
> For more information type '\warranty'
> 1>
> ```
<!-- }}} -->

Windows Authentication (*Domain Account*)

```sh
sqsh -S $target -U <DOMAIN>\\<user> -P '<password>'
```

Windows Authentication (*Local Account*)

```sh
sqsh -S $target -U <HOSTNAME>\\<user> -P '<password>!'
```

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
> 1> SELECT name FROM sys.databases;
> ```
> ```sh
> 2> GO
> ```
> ```sh
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

<!-- Example {{{-->
> [!example]-
>
> ```sql
> 1> USE my_database;
> ```
> ```sh
> 2> GO
> ```
> ```sql
> ENVCHANGE(DATABASE): Old Value: master, New Value: Employees
> INFO(ILF-SQL-01): Line 1: Changed database context to 'Employees'.
> ```
<!-- }}} -->

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
