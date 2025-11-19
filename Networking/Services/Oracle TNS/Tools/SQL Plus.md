---
id: SQL Plus
aliases: []
tags:
  - Networking/Oracle-TNS/Tools/ODAT
links: "[[Oracle TNS]]"
---

# SQL Plus

[SQL Plus](https://en.wikipedia.org/wiki/SQL_Plus) is an
[Oracle Database Utility](https://docs.oracle.com/cd/B14117_01/server.101/b12170/qstart.htm)
CLI, commonly used by users, administrators and programmers

___

<!-- Install {{{-->
## Install

<!-- Repository {{{-->
### Repository

1. Install [Kali Pkg](https://pkg.kali.org/pkg/oracle-instantclient-sqlplus)

```sh
sudo apt install oracle-instantclient-sqlplus
```

2. Check installation path

```sh
/opt/oracle/instantclient_21_4
```

3. Set environment variables

```sh
export ORACLE_HOME=/opt/oracle/instantclient_21_4/
```

```sh
export LD_LIBRARY_PATH="$ORACLE_HOME"
```

```sh
export PATH="$ORACLE_HOME:$PATH"
```

<!-- }}} -->

<!-- Manual {{{-->
### Manual

Manual installation

```sh
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip && \
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip && \
sudo mkdir -p /opt/oracle && \
sudo unzip -d /opt/oracle instantclient-basic-linux.x64-21.4.0.0.0dbru.zip && \
sudo unzip -d /opt/oracle instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip && \
export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_4:$LD_LIBRARY_PATH && \
export PATH=$LD_LIBRARY_PATH:$PATH && \
source ~/.bashrc
```

<!-- Tip {{{-->
> [!tip]
>
> In case of this error, execute the following
> (*[source](https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared)*)
>
> ```
> sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory
> ```
> ```sh
> sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

<!-- Tip {{{-->
> [!tip]
>
> List of SQL Plus
> [commands](https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985)
>
<!-- }}} -->

___
<!-- }}} -->
