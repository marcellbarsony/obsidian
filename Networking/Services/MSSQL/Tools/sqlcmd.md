---
id: sqlcmd
aliases: []
tags: []
  - Networking/Services/MSSQL/Tools/sqlcmd
---

# Sqlcmd

The [sqlcmd utility](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver17)
allows enter Transact-SQL statements, system procedures,
and script files through a variety of available modes

___

<!-- Installation {{{-->
## Installation

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

___
<!-- }}} -->

<!-- Connect {{{-->
## Connect

Connect to MSSQL servers

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

___
<!-- }}} -->
