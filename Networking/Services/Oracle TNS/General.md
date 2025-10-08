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

# General

**TNS** ([Oracle Transparent Network Substrate](https://en.wikipedia.org/wiki/Transparent_Network_Substrate))
is a communication protocol that facilitates communication between
Oracle databases and applications over networks.

Initially introduced as part of the
[Oracle Net Services](https://docs.oracle.com/en/database/oracle/oracle-database/18/netag/introducing-oracle-net-services.html)
software suite, **TNS** supports various networking protocols between Oracle
databases and client applications, such as
[IPX/SPX](https://en.wikipedia.org/wiki/IPX/SPX) and TCP/IP protocol stacks.

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

> [!todo]

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

<!-- }}} -->
