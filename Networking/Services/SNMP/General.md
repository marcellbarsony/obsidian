---
id: SNMP
aliases:
  - Simple Network Management Protocol
tags:
  - Networking/Services/SNMP
links: "[[Services]]"
port:
  - 161
  - 162
---

# SNMP

**SNMP** ([Simple Network Management Protocol](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol))
is an [Internet Standard](https://en.wikipedia.org/wiki/Internet_Standard)
protocol for collecting information about managed network devices and modifying
their configuration.

**SNMP** transmits control commands using agents over UDP port `161`.

While in classical communication, it is always the client who actively requests
information from the server, **SNMP** also enables the use of traps over UDP
port `162`.

For the **SNMP** client and server to exchange values, the **SNMP** objects must
have unique addresses known on both sides.

<!-- MIB & OID {{{-->
## MIB & OID

### MIB

**MIB** ([Management Information Base](https://en.wikipedia.org/wiki/Management_information_base))
is an independent format for storing device information that ensures that SNMP
access works across manufacturers and with different client-server combinations.

**MIB** is a text file (written in the ASN.1 ([Abstract Syntax Notation One](https://en.wikipedia.org/wiki/ASN.1))
based ASCII text format) in which all queryable SNMP objects of a device are
listed in a standardized tree hierarchy

**MIB** contains at least one `OID` which provides information about the type,
access rights, and description of the respective object.

**MIB** do not contain data, they explain where to find which information and
what it looks like, which returns values for the specific `OID`, or which data
type is used.

### OID

**OID** ([Object Identifier](https://en.wikipedia.org/wiki/Object_identifier))
represents a node in a hierarchical namespace.

**OID**s consist of integers and are usually concatenated by dot notation.
The sequence of numbers uniquely identifies each node, allowing the node's
position in the tree to be determined.

**OID** associated **MIB**s are in the [Object Identifier Registry](https://www.alvestrand.no/objectid/)

> [!example]-
>
> ```
> 1 ISO
> 1.3 identified-organization (ISO/IEC 6523),
> 1.3.6 DoD,
> 1.3.6.1 internet,
> 1.3.6.1.4 private,
> 1.3.6.1.4.1 IANA enterprise numbers,
> 1.3.6.1.4.1.343 Intel Corporation
> ```
<!-- }}} -->

<!-- SNMP Versions {{{-->
## SNMP Versions

### Version 1

**SNMP** version 1 (`SNMPv1`) is the first version of the protocol and is still
in use in many small networks

> [!danger]
>
> `SNMPv1` has no built-in authentication mechanism and
> does not support encryption

### Version 2c

In **SNMP** versions 2c (`SNMPv2c`), access is controlled using a plain text
community string, and if the name is known, access can be gained to it

> [!info]- Info - Community Strings
>
>**Community strings** can be seen as passwords that are used to determine
>whether the requested information can be viewed or not.
>
>The lack of encryption of the data is also a problem, as every time community
> strings are sent over a network, they can be intercepted and read.

> [!danger]
>
> `SNMPv2c` community string has no built-in encryption

### Version 3

**SNMP** version 3 (`SNMPv3`) introduced authentication and encryption (via
[pre-shared key](https://en.wikipedia.org/wiki/Pre-shared_key)), however the
complexity of the protocol has also increased

> [!success]
>
> `SNMPv3` supports authentication and encryption

<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

### SNMP Daemon Configuration

The **SNMP Daemon's default configuration** defines the basic settings for
the service.

The configuration file is located at `/etc/snmp/snmpd.conf` and the settings are
defined in the [snmpd manpage](https://www.net-snmp.org/docs/man/snmpd.conf.html).

> [!example]-
>
>```sh
>cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
>```
>```sh
>sysLocation    Sitting on the Dock of the Bay
>sysContact     Me <me@example.org>
>sysServices    72
>master  agentx
>agentaddress  127.0.0.1,[::1]
>view   systemonly  included   .1.3.6.1.2.1.1
>view   systemonly  included   .1.3.6.1.2.1.25.1
>rocommunity  public default -V systemonly
>rocommunity6 public default -V systemonly
>rouser authPrivUser authpriv -V systemonly
>```

### Dangerous Settings

Dangerous configurations that may be set

> [!danger]-
>
> | Settings                                         | Description                                                                          |
> | ------------------------------------------------ | ------------------------------------------------------------------------------------ |
> | `rwuser noauth`                                  | Provides access to the full OID tree without authentication                          |
> | `rwcommunity <community string> <IPv4 address>`  | Provides access to the full OID tree regardless of where the requests were sent from |
> | `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6                    |

<!-- }}} -->
