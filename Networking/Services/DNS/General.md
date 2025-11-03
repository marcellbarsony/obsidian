---
id: DNS
aliases:
  - Domain Name System
tags:
  - Networking/Services/DNS/General
links: "[[Services]]"
port:
  - UDP/53
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

<!-- DNS Domain {{{-->
## DNS Domain

A [Domain Name](https://en.wikipedia.org/wiki/Domain_name)
is a string that identifies a realm of administrative autonomy,
authority, or control

### Subdomain

A [Subdomain](https://en.wikipedia.org/wiki/Subdomain)
is a domain that is a part of another (*main*) domain

> [!example]-
>
> `en` is the subdomain, while `wikipedia` is the main domain
>
> ![[dns-subdomain.png]]

___
<!-- }}} -->

<!-- DNS Resolution {{{-->
## DNS Resolution

The **DNS Resolution** process is a translation service
between the domain name hierarchy and the IP address namespaces

> [!info]-
>
> ![[dns-flowchart.svg]]

<!-- Hosts File {{{-->
### Hosts File

The [hosts](https://en.wikipedia.org/wiki/Hosts_(file))
file maps domain names (*hostnames*) to IP addresses manually

The `hosts` file is located at

- **Linux**: `/etc/hosts`
- **Windows**: `C:\Windows\System32\drivers\etc\hosts`

```sh
<IP Address>    <Hostname> [<Alias> ...]
```

<!-- Example {{{-->
> [!example]-
>
> Redirect a domain to a local server
>
> ```sh
> 127.0.0.1       myapp.local
> ```
>
> Test connectivity to a specific IP address
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
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- DNS Structure {{{-->
## DNS Structure

> [!info]-
>
> ![[dns-structure.png]]

<!-- Root Name Server {{{-->
### Root Name Server

The [Root Server](https://en.wikipedia.org/wiki/Root_name_server)
responsible for the
[Top-Level Domain (TLD)](https://en.wikipedia.org/wiki/Top-level_domain).
As the last instance, they are only requested if the [[#Name Server]]
does not respond. The [13 root servers](https://www.iana.org/domains/root/servers)
are coordinated by [ICANN](https://www.icann.org/).

<!-- }}} -->

<!-- Name Server {{{-->
### Name Server

[Name Server](https://en.wikipedia.org/wiki/Name_server)
provides responses to queries against a
[directory service](https://en.wikipedia.org/wiki/Directory_service).

<!-- Authoritative Name Server {{{-->
#### Authoritative Name Server

[Authoritative Name Servers](https://en.wikipedia.org/wiki/Name_server#Authoritative_name_server)
hold authority for a particular zone.
If an **Authoritative Name Server** cannot answer a client's query,
the request is forwarded to the [[#Root Name Server]].
**Authoritative Name Server** provide answers to [[#Recursive Name Server]],
assisting in finding the specific web server(s).

<!-- }}} -->

<!-- Recursive Name Server {{{-->
#### Recursive Name Server

[Recursive Name Server](https://en.wikipedia.org/wiki/Name_server#Recursive_Resolver)
(*or Recursive Resolver*) collect information on specific DNS zones
via recursive or iterative DNS querying — they are not responsible
for a particular DNS zone.

<!-- }}} -->

<!-- }}} -->

<!-- Caching DNS Server {{{-->
### Caching DNS Server

**Caching DNS servers** cache information from other name servers
for a specified period (*specified by the [[#Authoritative Name Server]]*).

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

<!-- Example {{{-->
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
<!-- }}} -->

### A

### AAAA

### ANY

> [!warning]
>
> Many DNS servers ignore `ANY` queries to reduce load
> and prevent abuse ([RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482))

<!-- CNAME {{{-->
### CNAME

**Canonical Name record**
([CNAME record](https://en.wikipedia.org/wiki/CNAME_record))
serves as an alias for another domain name
(*e.g., An `A` record for `hackthebox.eu` and a `CNAME` record for
`www.hackthebox.eu` would make `www.hackthebox.eu`
point to the same IP as `hackthebox.eu`*)

<!-- }}} -->

### MX

### NS

<!-- SOA {{{-->
### SOA

**Start of Authority**
([SOA record](https://en.wikipedia.org/wiki/SOA_record))
([RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035))
is a DNS resource record containing administrative information
about the zone and [[#DNS Zone Transfer|DNS Zone Transfers]].

<!-- }}} -->

### TXT

___
<!-- }}} -->

<!-- DNS Zone Transfer {{{-->
## DNS Zone

[DNS Zone](https://en.wikipedia.org/wiki/DNS_zone)
is an specific administrative space of the DNS namespace
in the Domain Name System
([DNS](https://en.wikipedia.org/wiki/Domain_Name_System)),
which a specific organization or administrator manages

> [!info]-
>
> Illustration of DNS zone for `en.wiki.org`
>
> ![[dns-zone.png]]

### DNS Zone Transfer

[DNS Zone Transfer](https://en.wikipedia.org/wiki/DNS_zone_transfer)
is a DNS transaction (**AXFR**) to replicate DNS databases within a zone
(*a domain and its subdomains*) from one name server to another
(e.g., *in case of DNS failure*)

> [!info]-
>
> ![[dns-zone-transfer.png]]

1. **Zone Transfer Request**:
   The secondary DNS server sends a zone transfer request (*AXFR*)
   to the primary server

2. **SOA Record Transfer**:
   The primary server responds by sending its [[#SOA|SOA record]]
   (*after potentially authenticating the secondary server*)

3. **DNS Record Transmission**:
   The primary server transfers all the DNS records in the zone
   to the secondary server

4. **Zone Transfer Complete**:
   The primary server signals the end of the zone transfer

5. **Acknowledgement**:
   The secondary server sends an acknowledgement (*ACK*) message
   to the primary server

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

1. General settings
2. Zone entries

<!-- Local DNS Configuration {{{-->
#### Local DNS Configuration

`/etc/bind/named.conf.local` define different zones

<!-- }}} -->

<!-- Zone Files {{{-->
#### Zone Files

A [Zone File](https://en.wikipedia.org/wiki/Zone_file)
(*e.g., `/etc/bind/db.domain.com`*) is a text file describing
a DNS zone with the
[BIND file format](https://en.wikipedia.org/wiki/Zone_file#File_format).

There must be precisely one `SOA`
[SOA record](https://en.wikipedia.org/wiki/SOA_record)
and at least one [[#DNS Records|NS record]].

The forward records allow the DNS server to identify which domain,
hostname, and role the IP addresses belong to.

<!-- }}} -->

<!-- Reverse Name Resolution Zone Files {{{-->
#### Reverse Name Resolution Zone Files

For the Fully Qualified Domain Name (*FQDN*) to be resolved from the IP address,
the DNS server must have a reverse lookup file (e.g., `/etc/bind/db.10.129.14`).

In this file, the computer name (*FQDN*) is assigned to the last octet
of an IP address, which corresponds to the respective host,
using a `PTR` record.

The`PTR` records are responsible for the reverse translation
of IP addresses into names.

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
