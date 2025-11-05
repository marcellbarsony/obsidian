---
id: Oracle TNS
aliases:
  - ""
tags:
  - Networking/Services/Oracle-TNS/General
links: "[[Services]]"
ports:
  - 1521
  - 1522-1529
---

# Oracle TNS

**TNS** ([Oracle Transparent Network Substrate](https://en.wikipedia.org/wiki/Transparent_Network_Substrate))
is a communication protocol that facilitates communication between
Oracle databases and applications over networks.

Initially introduced as part of the
[Oracle Net Services](https://docs.oracle.com/en/database/oracle/oracle-database/18/netag/introducing-oracle-net-services.html)
software suite, **TNS** supports various networking protocols between Oracle
databases and client applications, such as
[IPX/SPX](https://en.wikipedia.org/wiki/IPX/SPX) and TCP/IP protocol stacks.

___

<!-- TNS Listener {{{-->
## TNS Listener

By default, the **TNS Listener** listens for incoming connections on
port TCP/`1521` (*this port can be changed in the configuration file*).

The **TNS Listener** hands the connection off to the correct database instance
once a request is received.

The **TNS Listener** is configured to support various network protocols,
including `TCP`/`IP`, `UDP`, `IPX`/`SPX`, and `AppleTalk`.

The **TNS Listener** will only accept connections from authorized hosts and
perform basic authentication using a combination of hostnames, IP addresses,
usernames and passwords.

___
<!-- }}} -->

<!-- Oracle RDBMS {{{-->
## Oracle RDBMS

An [Oracle Relational Database Management System](https://www.oracle.com/database/what-is-a-relational-database/)
is a type of database that stores and provides access to data points that are
related to one another.

### System Identifier

In [[General#Oracle RDBMS|Oracle RDBMS]], a System Identifier (**SID**)
is a unique name that identifies a particular database instance.

Database administrators can use the **SID** to monitor and manage
(e.g, *start*, *stop*, *restart*, *adjust the memory allocation*, etc.)
the individual instances of a database, using tools like
[Oracle Enterprise Manager](https://www.oracle.com/enterprise-manager/).

The client specifes the database's **SID** (along with its connection string)
to identify which Oracle database it wants to connect to.

> [!info]
>
> If a client doesn't specify a **SID**, the default value defined in the
> [[General#Tnsnames.ora|tnsnames.ora]] is used.

> [!warning]
>
> If a client specifies an **incorrect SID**,
> the **connection attempt will fail**

___
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

The configuration files can be found in the `$ORACLE_HOME/network/admin`
directory:

- [[General#Tnsnames.ora|tnsnames.ora]] (*client-side*)
- [[General#Listener.ora|listener.ora]] (*server-side*)

Oracle **TNS** can be managed remotely in `Oracle 8i`/`9i`, but not in
`Oracle 10g`/`11g`.

<!-- Default Configuration {{{-->
### Default Configuration

The **Oracle TNS server** default configuration varies depending on the
version and edition of Oracle software installed.

**Oracle TNS** is often used with other Oracle services like

- Oracle DBSNMP
- Oracle Databases
- Oracle Application Server
- Oracle Enterprise Manager
- Oracle Fusion Middleware
- web servers
- and many more.

#### Tnsnames.ora

[tnsnames.ora](https://docs.oracle.com/cd/E11882_01/network.112/e10835/tnsnames.htm#NETRF007)
is a **client-side configuration file** that has unique entries of each database
or service, containing the necessary information for clients to connect:

- a name for the service
- the network location of the service
- the database or service name that clients should use when connecting

<!-- Example {{{-->
> [!example]-
>
> A service called `ORCL` is listening on port TCP/1521 on the IP address
> `10.129.11.102`
>
> Clients should use the service name `orcl` when connecting to the service
>
> ```txt
> ORCL =
>   (DESCRIPTION =
>     (ADDRESS_LIST =
>       (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
>     )
>     (CONNECT_DATA =
>       (SERVER = DEDICATED)
>       (SERVICE_NAME = orcl)
>     )
>   )
> ```
>
> > [!info]- Info - Optional Entries
> >
> > - authentication details
> > - connection pooling settings
> > - load balancing configurations
<!-- }}} -->

#### Listener.ora

[listener.ora](https://docs.oracle.com/en/database/oracle/oracle-database/19/rilin/how-oracle-database-uses-the-listener-file-listener-ora.html)
is a **server-side configuration file** that defines the listener process's
properties and parameters.

<!-- Example {{{-->
> [!example]-
>
> ```txt
> SID_LIST_LISTENER =
>   (SID_LIST =
>     (SID_DESC =
>       (SID_NAME = PDB1)
>       (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
>       (GLOBAL_DBNAME = PDB1)
>       (SID_DIRECTORY_LIST =
>         (SID_DIRECTORY =
>           (DIRECTORY_TYPE = TNS_ADMIN)
>           (DIRECTORY = C:\oracle\product\19.0.0\dbhome_1\network\admin)
>         )
>       )
>     )
>   )
> 
> LISTENER =
>   (DESCRIPTION_LIST =
>     (DESCRIPTION =
>       (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
>       (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
>     )
>   )
>
> ADR_BASE_LISTENER = C:\oracle
> ```
<!-- }}} -->

#### PlsqlExclusionList

Ocale databases can be protected by using **PL**/**SQL Exclusion List**:

It is a user-created text file that needs to be placed in the
`$ORACLE_HOME/sqldeveloper` directory, and it contains the names of
**PL**/**SQL** packages or types that should be excluded from execution.
Once the **PL**/**SQL Exclusion List** file is created, it can be loaded into
the database instance. It serves as a blacklist that cannot be accessed through
the Oracle Application Server.

<!-- Settings {{{-->
| Setting            | Description
| ------------------ | -------------------------------------------------------------------------- |
| DESCRIPTION        | A descriptor that provides a name for the database and its connection type |
| ADDRESS            | The network address of the database, which includes the hostname and port number |
| PROTOCOL           | The network protocol used for communication with the server
| PORT               | The port number used for communication with the server
| CONNECT_DATA       | Specifies the attributes of the connection, such as the service name or SID, protocol, and database instance identifier |
| INSTANCE_NAME      | The name of the database instance the client wants to connect |
| SERVICE_NAME       | The name of the service that the client wants to connect to |
| SERVER             | The type of server used for the database connection, such as dedicated or shared |
| USER               | The username used to authenticate with the database server |
| PASSWORD           | The password used to authenticate with the database server |
| SECURITY           | The type of security for the connection |
| VALIDATE_CERT      | Whether to validate the certificate using SSL/TLS |
| SSL_VERSION        | The version of SSL/TLS to use for the connection |
| CONNECT_TIMEOUT    | The time limit in seconds for the client to establish a connection to the database |
| RECEIVE_TIMEOUT    | The time limit in seconds for the client to receive a response from the database |
| SEND_TIMEOUT       | The time limit in seconds for the client to send a request to the database |
| SQLNET.EXPIRE_TIME | The time limit in seconds for the client to detect a connection has failed.
| TRACE_LEVEL        | The level of tracing for the database connection |
| TRACE_DIRECTORY    | The directory where the trace files are stored |
| TRACE_FILE_NAME    | The name of the trace file |
| LOG_FILE           | The file where the log information is stored |
<!-- }}} -->

<!-- }}} -->

<!-- Dangerous Settings {{{-->
### Dangerous Settings

#### Default Password

Oracle default passwords

> [!danger]
>
> - **Oracle 9** has a default password **`CHANGE_ON_INSTALL`**
> - **Oracle 10** has **no default password** set
> - **Oracle DBSNMP** service uses the default password **`dbsnmp`**

#### Finger

The [finger service](https://en.wikipedia.org/wiki/Finger_(protocol)) is still
used by organizations together with oracle,
[[Enumeration#Finger|which can put Oracle's service at risk]].

<!-- }}} -->

___
<!-- }}} -->
