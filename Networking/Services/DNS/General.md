---
id: DNS-General
aliases:
  - Domain Name System
tags:
  - Networking/Services/DNS/General
links: "[[Services]]"
port:
  - 53
---

# Domain Name System (DNS)

- [Wikipedia - Domain Name System](https://en.wikipedia.org/wiki/Domain_Name_System)

<!-- DNS Structure {{{-->
## DNS Structure

![[dns-structure.png]]

### DNS Root Server

The **Root Servers** responsible for the top-level domains
([TLD](https://en.wikipedia.org/wiki/Top-level_domain)). As the last instance,
they are only requested if the name server does not respond. The 13 root servers
are coordinated by the The Internet Corporation for Assigned Names and Numbers
([ICANN](https://www.icann.org/)).

### Authoritative Name Server

**Authoritative Name Servers** hold authority for a particular zone.
If an **Authoritative Name Server** cannot answer a client's query, the
request is forwardet to the root name server. **Authoritative Name Server**
provide answers to recursive DNS nameservers, assisting in finding the specific
web server(s).

### Non-authoritative Nameserver

**Non-Authoritative Name Servers** collect information on specific DNS zones via
recursive or iterative DNS querying - they are not responsible for a particular
DNS zone

### Caching DNS Server

**Caching DNS servers** cache information from other name servers for a
specified period (sepcified by the authoritative name server)

### Forwarding Server

**Forwarding servers** forward DNS queries to another DNS server

### Resolver

**Resolvers** perform name resolution locally in the computer or router -
they are not authoritative DNS servers
<!-- }}} -->

<!-- DNS Records {{{-->
## DNS Records

Different **DNS Records** serve different purposes:

- **A**: Return an IPv4 address of the requested domain

- **AAAA**: Return an IPv6 address of the requested domain

- **MX**: Return the responsible mail servers

- **NS**: Return the DNS servers (nameservers) of the domain

- **TXT**: Can contain various information (e.g., validate Google Search
    Console, validate SSL certificates, SPF and DMARC entries (validate mail
    traffic and protect from spam)

- **CNAME**: Serves as an alias for another domain name
    (e.g., An `A` record for `hackthebox.eu` and a `CNAME` record for
    `www.hackthebox.eu` would make `www.hackthebox.eu` point to the same IP as
    `hackthebox.eu`)

- **PTR**: Converts IP addresses into valid domain names (Reverse Lookup)

- **SOA**: DNS zone information and email address of the administrative contact
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

All DNS servers work with three different types of configuration files:

- Local DNS configuration files
- Zone files
- Reverse name resolution files

### Default Configuration

The configuration files of the DNS server [Bind9](https://www.isc.org/bind/)
are

- `etc/bind/named.conf.local`
- `etc/bind/named.conf.options`
- `etc/bind/named.conf.log`

The configuration is roughly divided into two sections: general settings and
zone entries.

#### Local DNS Configuration

`/etc/bind/named.conf.local` define different zones

#### Zone Files

A **Zone File** (e.g., `/etc/bind/db.domain.com`) is a text file desrcibing a
DNS zone with the BIND file format. There must be precisely one `SOA` record and
at least one `NS` record. The forward records allow the DNS server to identify
which domain, hostname, and role the IP addresses belong to.

#### Reverse Name Resolution Zone Files

For the Fully Qualified Domain Name (FQDN) to be resolved from the IP address,
the DNS server must have a reverse lookup file (e.g., `/etc/bind/db.10.129.14`).

In this file, the computer name (FQDN) is assigned to the last octet of an IP
adress, which corresponds to the respective host, using a `PTR` record.

The`PTR` records are responsible for the reverse translation of IP addresses
into names.

### Dangerous Settings

Some settings can lead to vulnerabilities

| Option            | Description                                                                   |
| ----------------- | ----------------------------------------------------------------------------- |
| `allow-query`     | Defines which hosts are allowed to send requests to the DNS server            |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server  |
| `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server |
| `zone-statistics` | Collects statistical data of zones                                            |
<!-- }}} -->
