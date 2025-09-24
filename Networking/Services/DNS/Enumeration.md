---
id: DNS-Enumeration
aliases:
  - Domain Name System
tags:
  - Networking/Services/DNS/Enumeration
links: "[[Services]]"
---

# DNS Enumeration

DNS servers can be footprinted via queries

<!-- DNS Queries {{{-->
## DNS Queries

### DIG - Version Query

Query the version of the DNS server using the `CHAOS` query and type `TXT`

```sh
dig CH TXT version.bind @10.129.120.85
```

- `CH`: CHAOS class
- `TXT`: Record type
- `version.bind`: Special built-in name that DNS servers may respond to with
    their version info

### DIG - NS Query

Query DNS server for NS records

```sh
dig ns <domain> @<dns_server_ip>
```

**EXAMPLE**: Ask the DNS server `10.129.14.128` for the NS records for the
domain `inlanefreight.htb`

```sh
dig ns inlanefreight.htb @10.129.14.128
```

### DIG - ANY Query

Query all available records

```sh
dig any <domain> @<dns_server_ip>
```

**EXAMPLE**: Ask the DNS server `10.129.14.128` for all available records for
the domain `inlanefreight.htb`

```sh
dig any inlanefreight.htb @10.129.14.128
```

**NOTE**: Not all entries from the zones will be shown

### DIG - AXFR Zone Transfer

[**DNS Zone Transfer**](https://en.wikipedia.org/wiki/DNS_zone_transfer)
or **Asynchronous Full Transfer Zone** (**AXFR**) refers to the transfer of
zones to another server in DNS (e.g., in case of DNS failure).

The zone file must be kept identical on several name servers: synchronization
between the servers involved is realized by zone transfers, using a secret
`rndc-key`.

- **Primary server**: The original data on the zone is located on the primary
  server (master)
- **Secondary server**: Secondary name servers (mandatory for some TLDs)
  installed to increase reliability, realize simple load distribution, or
  protect the primary from attacks (master or slave)

DNS entries are only created, modified, or deleted on the **primary name
server**. This can be done manually, or by a dynamic update from a database.

- **Master DNS server**: The DNS server that serves as direct source for
  synchronizing
- **Slave DNS server**: The DNS server that obtains zone data from a master




```sh
dig axfr inlanefreight.htb @10.129.14.128
```

### DIG - AXFR Zone Transfer - Internal

<!-- }}} -->

<!-- Subdomain Brute Forcing {{{-->
## Subdomain Brute Forcing

```sh
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do \
    dig $sub.inlanefreight.htb @10.129.14.128 | \
    grep -v ';\|SOA' | \
    sed -r '/^\s*$/d' | \
    grep $sub | \
    tee -a subdomains.txt; \
done
```

[DNSenum](https://github.com/fwaeytens/dnsenum)

```sh
dnsenum \
    --dnsserver 10.129.14.128 \
    --enum -p 0 -s 0 \
    -o subdomains.txt \
    -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
    inlanefreight.htb
```

<!-- }}} -->

<!-- DNS Lookup {{{-->
## DNS Lookup

- [DNSDumpster](https://dnsdumpster.com/)

### DNS Lookup

Resolve a **domain name** to the corresponding **IP address**.

```sh
nslookup <target_domain>
```

### Reverse DNS Lookup

Resolve an **IP address** to the corresponding **domain name**.

```sh
nslookup -type=PTR <target_ip>
```
<!-- }}} -->
