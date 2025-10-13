---
id: DNS-Enumeration
aliases:
  - Domain Name System
tags:
  - Networking/Services/DNS/Enumeration
links: "[[Services]]"
---

# Enumeration

## Checklist

- [ ] [[#Banner Grabbing]]

<!-- Banner Grabbing {{{-->
## Banner Grabbing

Determine DNS server versions with `dig`

```sh
dig version.bind CHAOS TXT @<target_ip>
```

Grab banner with [dns-nsid](https://nmap.org/nsedoc/scripts/dns-nsid.html)
[[Nmap Scripting Engine|Nmap script]]

```sh
nmap --script dns-nsid <DNS_IP>
```

Grab banner with [[netcat]]

```sh
nc -nv -u <DNS_IP> 53
```

<!-- }}} -->

<!-- DNS Queries {{{-->
## DNS Queries

DNS servers can be footprinted via queries

<!-- DIG - Version Query {{{-->
### DIG - Version Query

Query the version of the DNS server using the `CHAOS` query and type `TXT`

```sh
dig CH TXT version.bind @10.129.120.85
```

> [!info]-
>
> - `CH`: CHAOS class
> - `TXT`: Record type
> - `version.bind`: Special built-in name that DNS servers may respond to with
>     their version info

<!-- }}} -->

<!-- DIG - NS Query {{{-->
### DIG - NS Query

Query DNS server for NS records

```sh
dig ns <domain> @<dns_server_ip>
```

<!-- Example {{{ -->
> [!example]
>
> Ask the DNS server `10.129.14.128` for the NS records for the
> domain `inlanefreight.htb`
>
> ```sh
> dig ns inlanefreight.htb @10.129.14.128
> ```
<!-- }}} -->

<!-- }}} -->

<!-- DIG - ANY Query {{{-->
### DIG - ANY Query

Query all available records

```sh
dig any <domain> @<dns_server_ip>
```

<!-- Example {{{-->
> [!example]-
>
> Ask the DNS server `10.129.14.128` for all available records for
> the domain `inlanefreight.htb`
>
> ```sh
> dig any inlanefreight.htb @10.129.61.117
> ```
> ```sh
> ; <<>> DiG 9.20.9-1-Debian <<>> any inlanefreight.htb @10.129.61.117
> ;; global options: +cmd
> ;; Got answer:
> ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55871
> ;; flags: qr aa rd; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 2
> ;; WARNING: recursion requested but not available
>
> ;; OPT PSEUDOSECTION:
> ; EDNS: version: 0, flags:; udp: 4096
> ; COOKIE: b951bf255c556e370100000068ed466c00314ed3ada99e2b (good)
> ;; QUESTION SECTION:
> ;inlanefreight.htb.             IN      ANY
>
> ;; ANSWER SECTION:
> inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
> inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
> inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
> inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
> inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
>
> ;; ADDITIONAL SECTION:
> ns.inlanefreight.htb.   604800  IN      A       127.0.0.1
>
> ;; Query time: 44 msec
> ;; SERVER: 10.129.61.117#53(10.129.61.117) (TCP)
> ;; WHEN: Mon Oct 13 14:35:23 EDT 2025
> ;; MSG SIZE  rcvd: 437
> ```
>
> - The FQDN of `inlanefreight.htb` is `ns.inlanefreight.htb`
}}}

<!-- Warning {{{-->
> [!warning]
>
> Not all entries from the zones will be shown
<!-- }}} -->

<!-- }}} -->

<!-- DIG - AXFR Zone Transfer {{{-->
### DIG - AXFR Zone Transfer

[**DNS Zone Transfer**](https://en.wikipedia.org/wiki/DNS_zone_transfer)
or **Asynchronous Full Transfer Zone** (**AXFR**) refers to the transfer of
zones to another server in DNS (e.g., *in case of DNS failure*).

<!-- Info {{{-->
> [!info]-
>
> The zone file must be kept identical on several name servers: synchronization
> between the servers involved is realized by zone transfers, using a secret
> `rndc-key`.
>
> - **Primary server**: The original data on the zone is located on the primary
>   server (master)
>
> - **Secondary server**: Secondary name servers (mandatory for some TLDs)
>   installed to increase reliability, realize simple load distribution, or
>   protect the primary from attacks (master or slave)
>
> DNS entries are only created, modified, or deleted on the **primary name
> server**. This can be done manually, or by a dynamic update from a database.
>
> - **Master DNS server**: The DNS server that serves as direct source
>   for synchronizing
>
> - **Slave DNS server**: The DNS server that obtains zone data from a master
<!-- }}} -->

**AXFR query** is a DNS protocol request used to retrieve all records of a domain from a DNS server:

```sh
dig axfr inlanefreight.htb @10.129.14.128
```

<!-- AXFR Zone Transfer - Internal {{{-->
#### AXFR Zone Transfer - Internal

> [!todo]

<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- Subdomain Brute Forcing {{{-->
## Subdomain Brute Forcing

<!-- Example {{{ -->
> [!example]-
>
> ```sh
> for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do \
>     dig $sub.inlanefreight.htb @10.129.14.128 | \
>     grep -v ';\|SOA' | \
>     sed -r '/^\s*$/d' | \
>     grep $sub | \
>     tee -a subdomains.txt; \
> done
> ```
<!-- }}} -->

[DNSenum](https://github.com/fwaeytens/dnsenum)

<!-- Example {{{-->
> [!example]-
>
> ```sh
> dnsenum \
>     --dnsserver 10.129.14.128 \
>     --enum -p 0 -s 0 \
>     -o subdomains.txt \
>     -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
>     inlanefreight.htb
> ```
<!-- }}} -->

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
