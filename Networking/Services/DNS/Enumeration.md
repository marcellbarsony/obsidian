---
id: DNS-Enumeration
aliases:
  - Domain Name System
tags:
  - Networking/Services/DNS/Enumeration
links: "[[Services]]"
---

# Enumeration

___

<!-- Banner Grabbing {{{-->
## Banner Grabbing

Grab banner and
[BIND](https://en.wikipedia.org/wiki/BIND)
server version with
[dig](https://man.archlinux.org/man/dig.1)

```sh
dig @<dns_ip> version.bind CHAOS TXT
```

Grab banner with the [dns-nsid](https://nmap.org/nsedoc/scripts/dns-nsid.html)
[[Nmap Scripting Engine|Nmap script]]

```sh
nmap --script dns-nsid <dns_ip>
```

Grab banner with [[netcat]]

```sh
nc -nv -u <dns_ip> 53
```

___

<!-- }}} -->

<!-- DNS Server Discovery {{{-->
## DNS Server Discovery

Identifying the DNS servers associated with the target domain

Query the [[General#Authoritative Name Server|Name Server]] with
[dig](https://linux.die.net/man/1/dig)

```sh
dig <target_domain> NS
```

Query the [[General#Authoritative Name Server|Name Server]] with
[nslookup](https://en.wikipedia.org/wiki/Nslookup)

```sh
nslookup -type=NS <target_domain>
```

___

<!-- }}} -->

<!-- DNS Subdomain {{{-->
## DNS Subdomain

<!-- Search Engine Discovery {{{-->
### Search Engine Discovery

Find [[General#Subdomain|Subdomains]] via [[Search Engine Discovery]]
(*[[Search Engine Discovery#Google Dorking|Google Dorking]]*)

> [!tip] Operators
>
> - `site:`: Find subdomains
> - `-`: Exclude already known subdomains
>
> > [!example]-
> >
> > ```sh
> > site:wikipedia.org -en.wikipedia.org
> > ```

<!-- }}} -->

<!-- Certificate Transparency {{{-->
### Certificate Transparency

[Certificate Transparency](https://en.wikipedia.org/wiki/Certificate_Transparency)
([RFC-6962](https://datatracker.ietf.org/doc/html/rfc6962))
is a process intended to enable the verification of issued digital certificates
for encrypted Internet connections

> [!tip] Certificate Transparency Logs
>
> **Certificate Transparency Logs**
> may expose subdomains, which might host outdated software
> or configurations
>
> - [crt.sh](https://crt.sh)
> - [Censys](https://search.censys.io/)
> - [Facebook's CT Monitor](https://developers.facebook.com/tools/ct/)
> - [Google's CT Monitor](https://transparencyreport.google.com/https/certificates)

<!-- cURL {{{-->
> [!example]- [[cURL]]
>
> List SSL certificates
>
> ```sh
> curl -s https://crt.sh/\?q\=<example.com>\&output\=json | jq .
> ```
>
> > [!info]-
> >
> > - `-s`: Silent mode, suppress progress bars and error messages
>
> Filter SSL certificate by unique subdomains
>
> <!-- Example {{{-->
> > [!example]-
> >
> > Find all `dev` subdomains of `facebook.com`
> >
> > ```sh
> > curl -s "https://crt.sh/?q=facebook.com&output=json" | \
> >   jq -r '.[] | \
> >  select(.name_value | \
> >  contains("dev")) | \
> >  .name_value' | \
> >  sort -u
> > ```
> > ```sh
> > *.dev.facebook.com
> > *.newdev.facebook.com
> > *.secure.dev.facebook.com
> > dev.facebook.com
> > devvm1958.ftw3.facebook.com
> > facebook-amex-dev.facebook.com
> > facebook-amex-sign-enc-dev.facebook.com
> > newdev.facebook.com
> > secure.dev.facebook.com
> > ```
> >
> > > [!info]-
> > >
> > > - `curl -s "https://crt.sh/?q=facebook.com&output=json"`:
> > >   Fetch the JSON output from `crt.sh` for certificates
> > >   matching the domain `facebook.com`
> > > - `jq -r '.[] | select(.name_value | contains("dev")) | .name_value'`:
> > >   Filter the JSON results, select entries where the `name_value` field
> > >   (*which contains the domain or subdomain*) includes the string
> > >   `dev`.
> > > - `sort -u`: Sort the results alphabetically and remove duplicates
> <!-- }}} -->
>
> <!-- Example {{{-->
> > [!example]-
> >
> > ```sh
> > curl -s https://crt.sh/\?q\=<example.com>\&output\=json | \
> >   jq . | \
> >   grep name | \
> >   cut -d":" -f2 | \
> >   grep -v "CN=" | \
> >   cut -d'"' -f2 | \
> >   awk '{gsub(/\\n/,"\n");}1;' | \
> >   sort -ucurl -s https://crt.sh/\?q\=<example.com>\&output\=json | \
> >   jq . | \
> >   grep name | \
> >   cut -d":" -f2 | \
> >   grep -v "CN=" | \
> >   cut -d'"' -f2 | \
> >   awk '{gsub(/\\n/,"\n");}1;' | \
> >   sort -u
> > ```
> <!-- }}} -->
<!-- }}} -->

> [!example]- Subfinder
>
> ```sh
> subfinder -d "target.domain"
> ```

___
<!-- }}} -->

<!-- Brute Forcing {{{-->
### Brute Forcing

Brute Force DNS Subdomains

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
>
> [SecLists/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
>
> ```sh
> /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
> ```
> ```sh
> /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
> ```
> ```sh
> /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
> ```
> ```sh
> /usr/share/SecLists/Discovery/DNS/namelist.txt
> ```
<!-- }}} -->

<!-- Gobuster {{{-->
> [!example]- [[Gobuster#DNS Subdomain Enumeration|Gobuster]]
>
> ```sh
> gobuster dns [flags] -d <target> -w <wordlist.txt>
> ```
> ```sh
> gobuster dns [flags] -d <target> -w <wordlist.txt> -s <target_dns>
> ```
<!-- }}} -->

<!-- DNSEnum {{{-->
> [!example]- [[DNSEnum]]
>
> ```sh
> dnsenum --enum <target> -f <wordlist.txt> -r
> ```
> ```sh
> dnsenum --dnsserver <target_dns> --enum -p 5 -s 5 -o subdomains.txt -f <wordlist.txt> <target_domain>
> ```
>
> <!-- Info {{{-->
> > [!info]
> >
> > - `--dnsserver <dns_ip>`: Target DNS server to query
> > - `--enum`: Run all enumeration steps (`A`, `NS`, `MX`, and subdomain
> >   brute-forcing, and some zone-transfer attempts)
> > - `-p 5`: Number of threads for reverse lookup (`0` to disable)
> > - `-s 5`: Number of threads for subdomain brute-forcing (`0` to disable)
> > - `-o subdomains.txt`: Output file for results
> > - `-f <wordlist.txt>`: Wordlist file for subdomain brute-forcing
> <!-- }}} -->
<!-- }}} -->

<!-- Bash {{{-->
> [!example]- Bash
>
> Bash script for DNS subdomains brute-forcing
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

<!-- }}} -->

___

<!-- }}} -->

<!-- DNS Queries {{{-->
## DNS Queries

DNS servers can be footprinted via queries

<!-- Version Query {{{-->
### Version Query

Query the version of the DNS server using the `CHAOS` query and type `TXT`

```sh
dig @<dns_ip> version.bind TXT CH
```

<!-- Info {{{-->
> [!info]-
>
> - `version.bind`: Special built-in name that DNS servers may respond to with
>     their version info
> - `CH`: CHAOS class
> - `TXT`: Record type
<!-- }}} -->

<!-- }}} -->

<!-- NS Query {{{-->
### NS Query

Query the DNS server for NS records of a domain

```sh
dig [@<dns_ip>] <target_domain> ns
```

```sh
nslookup -type=NS <target_domain> [dns_ip]
```

<!-- Example {{{-->
> [!example]-
>
> Ask the DNS server `10.129.14.128` for the NS records for the
> domain `inlanefreight.htb`
>
> ```sh
> dig @10.129.14.128 inlanefreight.htb ns
> ```
> ```sh
> nslookup -type=NS inlanefreight.htb 10.129.14.128
> ```
<!-- }}} -->

<!-- }}} -->

<!-- ANY Query {{{-->
### ANY Query

Query the DNS server for all available records of a domain

```sh
dig @<dns_ip> <target_domain> any
```

<!-- Example {{{-->
> [!example]-
>
> Ask the DNS server `10.129.14.128` for all available records for
> the domain `inlanefreight.htb`
>
> ```sh
> dig @10.129.61.117 inlanefreight.htb any
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

<!-- AXFR Zone Transfer {{{-->
### AXFR Zone Transfer

[**DNS Zone Transfer**](https://en.wikipedia.org/wiki/DNS_zone_transfer)
or **Asynchronous Full Transfer Zone** (**AXFR**) refers to the transfer of
zones to another server in DNS (e.g., *in case of DNS failure*)

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

Request a [[DIG#AXFR|zone transfer with DIG]]

```sh
dig @<target_dns> <target_domain> -t axfr
```

<!-- Example {{{-->
> [!example]-
>
> Request a full zone transfer responsible for
> [zonetransfer.me](https://digi.ninja/projects/zonetransferme.php)
>
> ```sh
> dig axfr @nsztm1.digi.ninja zonetransfer.me
> ```
> ```sh
> ; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> axfr @nsztm1.digi.ninja zonetransfer.me
> ; (1 server found)
> ;; global options: +cmd
> zonetransfer.me.	7200	IN	SOA	nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
> zonetransfer.me.	300	IN	HINFO	"Casio fx-700G" "Windows XP"
> zonetransfer.me.	301	IN	TXT	"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
> zonetransfer.me.	7200	IN	MX	0 ASPMX.L.GOOGLE.COM.
> ...
> zonetransfer.me.	7200	IN	A	5.196.105.14
> zonetransfer.me.	7200	IN	NS	nsztm1.digi.ninja.
> zonetransfer.me.	7200	IN	NS	nsztm2.digi.ninja.
> _acme-challenge.zonetransfer.me. 301 IN	TXT	"6Oa05hbUJ9xSsvYy7pApQvwCUSSGgxvrbdizjePEsZI"
> _sip._tcp.zonetransfer.me. 14000 IN	SRV	0 0 5060 www.zonetransfer.me.
> 14.105.196.5.IN-ADDR.ARPA.zonetransfer.me. 7200	IN PTR www.zonetransfer.me.
> asfdbauthdns.zonetransfer.me. 7900 IN	AFSDB	1 asfdbbox.zonetransfer.me.
> asfdbbox.zonetransfer.me. 7200	IN	A	127.0.0.1
> asfdbvolume.zonetransfer.me. 7800 IN	AFSDB	1 asfdbbox.zonetransfer.me.
> canberra-office.zonetransfer.me. 7200 IN A	202.14.81.230
> ...
> ;; Query time: 10 msec
> ;; SERVER: 81.4.108.41#53(nsztm1.digi.ninja) (TCP)
> ;; WHEN: Mon May 27 18:31:35 BST 2024
> ;; XFR size: 50 records (messages 1, bytes 2085)
> ```
<!-- }}} -->

[[fierce]] automates zone transfers and performs dictionary attacks

```sh
fierce --domain <target_domain> --dns-servers <dns_ip>
```

<!-- }}} -->

___

<!-- }}} -->

<!-- DNS Lookup {{{-->
## DNS Lookup

### DNS Lookup

Resolve a **domain name** to the corresponding **IP address**.

```sh
nslookup <target_domain>
```

### Reverse DNS Lookup

Resolve an **IP address** to the corresponding **domain name**.

```sh
nslookup -type=PTR <target>
```

### Online Tools

- [DNSDumpster](https://dnsdumpster.com/)

___

<!-- }}} -->
