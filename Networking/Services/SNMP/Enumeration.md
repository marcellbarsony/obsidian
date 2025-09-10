---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SNMP
links: "[[SNMP]]"
---

# Enumeration

Examination of process parameters might reveal credentials, routing information
and services boundto additional interfaces when passed on the command line.

## Service scanning

Service scanning with [snmpwalk](https://linux.die.net/man/1/snmpwalk)

```sh
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0

iso.3.6.1.2.1.1.5.0 = STRING: "gs-svcscan"
```

```sh
snmpwalk -v 2c -c private  10.129.42.253 

Timeout: No Response from 10.129.42.253
```
