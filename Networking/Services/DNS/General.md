---
id: DNS
aliases:
  - Domain Name System
tags:
  - Networking/Services/DNS/General
links: "[[Services]]"
port:
  - 53
---

<!-- DNS {{{-->
# DNS

**DNS** ([Domain Name System](https://en.wikipedia.org/wiki/Domain_Name_System))
is a [name service](https://en.wikipedia.org/wiki/Directory_service)
that provides a naming system for computers, services and other resources
on the Internet:<br>
it is converting user-friendly domain names
(*like [example.com](http://exmaple.com)*)
into numerical IP addresses.

___

<!-- }}} -->

<!-- DNS Resolution {{{-->
## DNS Resolution

> [!info]-
>
> ![[dns-flowchart.svg]]

### Hosts File

The [hosts](https://en.wikipedia.org/wiki/Hosts_(file))
file maps hostnames to IP addresses manually


- `C:\Windows\System32\drivers\etc\hosts`
- `/etc/hosts`

```sh
<IP Address>    <Hostname> [<Alias> ...]
```

> [!example]-
>
> Redirect a domain to a local server
>
> ```sh
> 127.0.0.1       myapp.local
> ```
>
> Test connectvity to a specific IP address
>
> ```sh
> 192.168.1.20    testserver.local
> ```
>
> Block unwanted websites
>
> ```sh
> 0.0.0.0       unwanted-site.com
> ```

___
<!-- }}} -->

<!-- DNS Structure {{{-->
## DNS Structure

> [!info]-
>
> ![[dns-structure.png]]

<!-- DNS Root Server {{{-->
### DNS Root Server

The **Root Servers** responsible for the top-level domains
([TLD](https://en.wikipedia.org/wiki/Top-level_domain)).
As the last instance, they are only requested if the name server
does not respond. The 13 root servers are coordinated by the
The Internet Corporation for Assigned Names and Numbers
([ICANN](https://www.icann.org/)).

<!-- }}} -->

<!-- Authoritative Name Server {{{-->
### Authoritative Name Server

**Authoritative Name Servers** hold authority for a particular zone.
If an **Authoritative Name Server** cannot answer a client's query,
the request is forwarded to the root name server.
**Authoritative Name Server** provide answers to recursive DNS nameservers,
assisting in finding the specific web server(s).

<!-- }}} -->

<!-- Non-authoritative Nameserver {{{-->
### Non-authoritative Nameserver

**Non-Authoritative Name Servers** collect information on specific DNS zones
via recursive or iterative DNS querying — they are not responsible
for a particular DNS zone.

<!-- }}} -->

<!-- Caching DNS Server {{{-->
### Caching DNS Server

**Caching DNS servers** cache information from other name servers
for a specified period (specified by the authoritative name server).

<!-- }}} -->

<!-- Forwarding Server {{{-->
### Forwarding Server

**Forwarding servers** forward DNS queries to another DNS server.

<!-- }}} -->

<!-- Resolver {{{-->
### Resolver

**Resolvers** perform name resolution locally in the computer or router
— they are not authoritative DNS servers.

<!-- }}} -->

___

<!-- }}} -->

<!-- DNS Records {{{-->
## DNS Records

- **CNAME**: Serves as an alias for another domain name
    (e.g., An `A` record for `hackthebox.eu` and a `CNAME` record for
    `www.hackthebox.eu` would make `www.hackthebox.eu` point to the same IP as
    `hackthebox.eu`)

> [!example]-
>
> | Record Type | Full Name | Description | Zone File Example |
> | --- | --- | --- | --- |
> | **A** | Address Record | Maps a hostname to its IPv4 address. | www.example.com. IN A `192.0.2.1` |
> | **AAAA** | IPv6 Address Record | Maps a hostname to its IPv6 address. | www.example.com. IN AAAA `2001:db8:85a3::8a2e:370:7334` |
> | **CNAME** | Canonical Name Record | Creates an alias for a hostname, pointing it to another hostname. | `blog.example.com.` IN CNAME `webserver.example.net.` |
> | **MX** | Mail Exchange Record | Specifies the mail server(s) responsible for handling email for the domain. | `example.com.` IN MX 10 `mail.example.com.` |
> | **NS** | Name Server Record | Delegates a DNS zone to a specific authoritative name server. | `example.com.` IN NS `ns1.example.com.` |
> | **TXT** | Text Record | Stores arbitrary text information, often used for domain verification or security policies. | `example.com.` IN TXT `"v=spf1 mx -all"` (SPF record) |
> | **SOA** | Start of Authority Record | Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | `example.com.` IN SOA `ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |
> | **SRV** | Service Record | Defines the hostname and port number for specific services. | `_sip._udp.example.com.` IN SRV 10 5 5060 `sipserver.example.com.` |
> | **PTR** | Pointer Record | Used for reverse DNS lookups, mapping an IP address to a hostname. | `1.2.0.192.in-addr.arpa.` IN PTR `www.example.com.` |

___
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

All DNS servers work with three different types of configuration files:

- Local DNS configuration files
- Zone files
- Reverse name resolution files

<!-- Default Configuration {{{-->
### Default Configuration

The configuration files of the DNS server [Bind9](https://www.isc.org/bind/)
are

- `etc/bind/named.conf.local`
- `etc/bind/named.conf.options`
- `etc/bind/named.conf.log`

The configuration is roughly divided into two sections:

- general settings
- zone entries

<!-- Local DNS Configuration {{{-->
#### Local DNS Configuration

`/etc/bind/named.conf.local` define different zones

<!-- }}} -->

<!-- Zone Files {{{-->
#### Zone Files

A **Zone File** (e.g., `/etc/bind/db.domain.com`) is a text file desrcibing a
DNS zone with the BIND file format. There must be precisely one `SOA` record and
at least one `NS` record. The forward records allow the DNS server to identify
which domain, hostname, and role the IP addresses belong to.

<!-- }}} -->

<!-- Reverse Name Resolution Zone Files {{{-->
#### Reverse Name Resolution Zone Files

For the Fully Qualified Domain Name (FQDN) to be resolved from the IP address,
the DNS server must have a reverse lookup file (e.g., `/etc/bind/db.10.129.14`).

In this file, the computer name (FQDN) is assigned to the last octet of an IP
address, which corresponds to the respective host, using a `PTR` record.

The`PTR` records are responsible for the reverse translation of IP addresses
into names.

<!-- }}} -->

<!-- }}} -->

<!-- Dangerous Settings {{{-->
### Dangerous Settings

Some settings can lead to vulnerabilities

<!-- Danger {{{-->
> [!danger]-
>
> | Option            | Description                                                                   |
> | ----------------- | ----------------------------------------------------------------------------- |
> | `allow-query`     | Defines which hosts are allowed to send requests to the DNS server            |
> | `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server  |
> | `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server |
> | `zone-statistics` | Collects statistical data of zones                                            |
<!-- }}} -->

<!-- }}} -->

___

<!-- }}} -->
