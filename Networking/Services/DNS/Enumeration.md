---
id: DNS-Enumeration
aliases:
  - Domain Name System
tags:
  - Networking/Services/DNS/Enumeration
links: "[[Networking/Services/General]]"
---

# Enumeration

___

<!-- DNS Server Discovery {{{-->
## DNS Server Discovery

Identify the DNS servers associated with the target domain

[[dig]] —
Query the [[DNS/General#Authoritative Name Server|Name Server]]

```sh
dig <target_domain> NS
```

[[nslookup]] —
Query the [[DNS/General#Authoritative Name Server|Name Server]]

```sh
nslookup -type=NS <target_domain>
```
___
<!-- }}} -->

<!-- DNS Service {{{-->
## DNS Service

[[dig]] — Grab banner and
[BIND](https://en.wikipedia.org/wiki/BIND)
server version

```sh
dig @<dns_ip> version.bind CHAOS TXT
```

<!-- Info {{{-->
> [!info]-
>
> - `version.bind`: Special built-in name that DNS servers may respond to with
>     their version info
> - `CH`: CHAOS class
> - `TXT`: Record type
<!-- }}} -->

[[Nmap Scripting Engine|Nmap script]]
([dns-nsid](https://nmap.org/nsedoc/scripts/dns-nsid.html)) —
Grab banner

```sh
nmap --script dns-nsid <dns_ip>
```

[[Netcat]] — Grab banner

```sh
nc -nv -u <dns_ip> 53
```

___
<!-- }}} -->

<!-- DNS Subdomains {{{-->
## DNS Subdomains

Identify subdomains of the `*.domain.com` scope
to widen the attack surface

<!-- Search Engine Discovery {{{-->
### Search Engine Discovery

[[Search Engine Discovery]]
(*[[Search Engine Discovery#Google Dorking|Google Dorking]]*) —
Find [[Networking/Services/DNS/General#Subdomain|Subdomains]]

<!-- Operator {{{-->
> [!tip]- Operators
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

<!-- }}} -->

<!-- Certificate Transparency {{{-->
### Certificate Transparency

[Certificate Transparency](https://en.wikipedia.org/wiki/Certificate_Transparency)
([RFC-6962](https://datatracker.ietf.org/doc/html/rfc6962))
is a process intended to enable the verification of issued digital certificates
for encrypted Internet connections

<!-- Certificate Transparency Logs {{{-->
> [!tip]- Certificate Transparency Logs
>
> **Certificate Transparency Logs**
> may expose subdomains, which might host outdated software
> or configurations
>
> - [crt.sh](https://crt.sh)
> - [Censys](https://search.censys.io/)
> - [Facebook's CT Monitor](https://developers.facebook.com/tools/ct/)
> - [Google's CT Monitor](https://transparencyreport.google.com/https/certificates)
<!-- }}} -->

[[cURL]] — List SSL certificates

```sh
curl -s https://crt.sh/\?q\=<example.com>\&output\=json | jq .
```

<!-- Info {{{-->
> [!info]-
>
> - `-s`: Silent mode, suppress progress bars and error messages
<!-- }}} -->

[[cURL]] — List and filter
([jq](https://en.wikipedia.org/wiki/Jq_(programming_language)))
SSL certificate by unique subdomains

<!-- Example {{{-->
> [!example]-
>
> Find all `dev` subdomains of `facebook.com`
>
> ```sh
> curl -s "https://crt.sh/?q=facebook.com&output=json" | \
>   jq -r '.[] | \
>  select(.name_value | \
>  contains("dev")) | \
>  .name_value' | \
>  sort -u
> ```
> ```sh
> *.dev.facebook.com
> *.newdev.facebook.com
> *.secure.dev.facebook.com
> dev.facebook.com
> devvm1958.ftw3.facebook.com
> facebook-amex-dev.facebook.com
> facebook-amex-sign-enc-dev.facebook.com
> newdev.facebook.com
> secure.dev.facebook.com
> ```
>
> > [!info]-
> >
> > - `curl -s "https://crt.sh/?q=facebook.com&output=json"`:
> >   Fetch the JSON output from `crt.sh` for certificates
> >   matching the domain `facebook.com`
> > - `jq -r '.[] | select(.name_value | contains("dev")) | .name_value'`:
> >   Filter the JSON results, select entries where the `name_value` field
> >   (*which contains the domain or subdomain*) includes the string
> >   `dev`.
> > - `sort -u`: Sort the results alphabetically and remove duplicates
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> curl -s https://crt.sh/\?q\=<example.com>\&output\=json | \
>   jq . | \
>   grep name | \
>   cut -d":" -f2 | \
>   grep -v "CN=" | \
>   cut -d'"' -f2 | \
>   awk '{gsub(/\\n/,"\n");}1;' | \
>   sort -ucurl -s https://crt.sh/\?q\=<example.com>\&output\=json | \
>   jq . | \
>   grep name | \
>   cut -d":" -f2 | \
>   grep -v "CN=" | \
>   cut -d'"' -f2 | \
>   awk '{gsub(/\\n/,"\n");}1;' | \
>   sort -u
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Passive Enumeration {{{-->
### Passive Enumeration

DNS Subdomain enumeration using passive online resources

[[subfinder]] — DNS Subdomain enumeration

```sh
subfinder -d "<target_domain>"
```

[[Findomain]] — DNS Subdomain enumeration

```sh
findomain -t "<target_domain>" -a
```

[DNSDumpster](https://dnsdumpster.com/) —

```sh

```

<!-- }}} -->

<!-- Brute Force {{{-->
### Brute Force

Brute Force DNS Subdomains

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> [[SecLists#Subdomains|SecLists - Subdomain]]
>
<!-- }}} -->

[[Ffuf]]

```sh
ffuf -w <wordlist> -u http://FUZZ.$target/ -c -r
```

<!-- Info {{{-->
> [!info]-
>
> - `-c`: Colorize output (*default: `false`*)
> - `-r`: Follow redirects (*default: `false`*)
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> **Wordlists**
>
> Subdomains Top 1 Million
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/namelist.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> Shubs
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> Bitquark
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
> Combined
>
> ```sh
> ffuf -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt \
> -u http://FUZZ.$target/ \
> -c -ic
> ```
>
<!-- }}} -->

[[Gobuster#DNS Subdomain Enumeration|Gobuster]] —
DNS Subdomain Brute Forcing

```sh
gobuster dns [flags] -d $target -w <wordlist> [-s <target_dns>]
```

<!-- Example {{{-->
> [!example]-
>
> **Wordlists**
>
> Subdomains Top 1 Million
>
> ```sh
> gobuster dns \
> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
> -d <target_domain> \
> -s <target_dns>
> ```
>
> ```sh
> gobuster dns \
> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
> -d <target_domain> \
> -s <target_dns>
> ```
>
> ```sh
> gobuster dns \
> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
> -d <target_domain> \
> -s <target_dns>
> ```
>
> ```sh
> gobuster dns \
> -w /usr/share/SecLists/Discovery/DNS/namelist.txt \
> -d <target_domain> \
> -s <target_dns>
> ```
>
> Additional lists
>
> ```sh
> gobuster dns \
> -w /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt \
> -d <target_domain> \
> -s <target_dns>
> ```
>
> ```sh
> gobuster dns \
> -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt \
> -d <target_domain> \
> -s <target_dns>
> ```
>
> Combined List
>
> ```sh
> gobuster dns \
> -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt \
> -d <target_domain> \
> -s <target_dns>
> ```
>
> <!-- Info {{{-->
> > [!info]-
> >
> > The combined list consists of
> >
> > - `bitquark-subdomains-top100000.txt`
> > - `shubs-subdomains.txt`
> > - `subdomains-top1million-110000.txt`
> >
> <!-- }}} -->
>
> **Example**
>
> ```sh
> gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
> ```
<!-- }}} -->

[[DNSEnum]] —
DNS Subdomain Brute Forcing

```sh
dnsenum --enum --dnsserver $target -f <wordlist> -r
```

<!-- Info {{{-->
> [!info]-
>
> - `--enum`: Run all enumeration steps
>   (*`A`, `NS`, `MX`, and subdomain brute-forcing,
>   and some zone-transfer attempts*)
> - `-o subdomains.txt`: Output file for results
> - `-f <wordlist>`: Wordlist file for subdomain brute-forcing
> - `-r`: Recursion on subdomains
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> **Wordlists**
>
> General Subdomain & Virtual Host Lists
>
> ```sh
> dnsenum --enum $target \
> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
> <target_domain> \
> -o subdomains.txt
> ```
>
> ```sh
> dnsenum --enum $target \
> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
> <target_domain> \
> -o subdomains.txt
> ```
>
> ```sh
> dnsenum --enum $target \
> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
> <target_domain> \
> -o subdomains.txt
> ```
>
> ```sh
> dnsenum --enum $target \
> -f /usr/share/SecLists/Discovery/DNS/namelist.txt \
> <target_domain> \
> -o subdomains.txt
> ```
>
> Additional lists
>
> ```sh
> dnsenum --enum $target \
> -f /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt \
> <target_domain> \
> -o subdomains.txt
> ```
>
> ```sh
> dnsenum --enum $target \
> -f /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt \
> <target_domain> \
> -o subdomains.txt
> ```
>
> Combined List
>
> ```sh
> dnsenum --enum $target \
> -f /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt \
> <target_domain> \
> -o subdomains.txt
> ```
>
> <!-- Info {{{-->
> > [!info]-
> >
> > The combined list consists of
> >
> > - `bitquark-subdomains-top100000.txt`
> > - `shubs-subdomains.txt`
> > - `subdomains-top1million-110000.txt`
> >
> <!-- }}} -->
>
<!-- }}} -->

```sh
dnsenum --enum --dnsserver $target <target_domain> -f <wordlist.txt> -p 5 -s 5 -o subdomains.txt
```

<!-- Info {{{-->
> [!info]-
>
> - `--dnsserver <dns_ip>`: Target DNS server to query
> - `--enum`: Run all enumeration steps
>   (*`A`, `NS`, `MX`, and subdomain brute-forcing,
>   and some zone-transfer attempts*)
> - `-p 5`: Threads for reverse lookup
>   (*`0` to disable*)
> - `-s 5`: Threads for subdomain brute-forcing
>   (*`0` to disable*)
> - `-o subdomains.txt`: Output file for results
> - `-f <wordlist>`: Wordlist file for subdomain brute-forcing
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> General Subdomain & Virtual Host Lists
>
> ```sh
> dnsenum \
> --dnsserver $target \
> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
> --enum -p 5 -s 5 \
> <target_domain> \
> -o subdomains.txt
> ```
>
> ```sh
> dnsenum \
> --dnsserver $target \
> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
> <target_domain> \
> --enum -p 5 -s 5 \
> -o subdomains.txt
> ```
>
> ```sh
> dnsenum \
> --dnsserver $target \
> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
> <target_domain> \
> --enum -p 5 -s 5 \
> -o subdomains.txt
> ```
>
> ```sh
> dnsenum \
> --dnsserver $target \
> -f /usr/share/SecLists/Discovery/DNS/namelist.txt \
> <target_domain> \
> --enum -p 5 -s 5 \
> -o subdomains.txt
> ```
>
> Additional lists
>
> ```sh
> dnsenum \
> -f /usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt \
> --dnsserver $target \
> <target_domain> \
> --enum -p 5 -s 5 \
> -o subdomains.txt
> ```
>
> ```sh
> dnsenum \
> -f /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt \
> --dnsserver $target \
> <target_domain> \
> --enum -p 5 -s 5 \
> -o subdomains.txt
> ```
>
> Combined List
>
> ```sh
> dnsenum \
> -f /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt \
> --dnsserver $target \
> <target_domain> \
> --enum -p 5 -s 5 \
> -o subdomains.txt
> ```
>
> <!-- Info {{{-->
> > [!info]-
> >
> > The combined list consists of
> >
> > - `bitquark-subdomains-top100000.txt`
> > - `shubs-subdomains.txt`
> > - `subdomains-top1million-110000.txt`
> >
> <!-- }}} -->
>
<!-- }}} -->

[Bash](https://en.wikipedia.org/wiki/Bash_(Unix_shell)) —
DNS Subdomain Brute Forcing

<!-- Example {{{-->
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

<!-- }}} -->

___
<!-- }}} -->

<!-- DNS Queries {{{-->
## DNS Queries

DNS servers can be footprinted via queries

<!-- NS Query {{{-->
### NS Query

[dig](https://linux.die.net/man/1/dig) —
Query the DNS server for [[Networking/Services/DNS/General#NS|NS]] records of a domain

```sh
dig [@<dns_ip>] <target_domain> ns
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
<!-- }}} -->

<!-- }}} -->

<!-- ANY Query {{{-->
### ANY Query

[dig](https://linux.die.net/man/1/dig) —
Query the DNS server for [[Networking/Services/DNS/General#ANY|ANY]] (*all available*) records
of a domain

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

[[Networking/Services/DNS/General#DNS Zone Transfer|DNS Zone Transfer]]
or **Asynchronous Full Transfer Zone** (*[[Networking/Services/DNS/General#AXFR|AXFR]]*)
yields a full DNS zone dump
(*e.g. all hostnames, IPs, subdomains, etc.*)

<!-- Test {{{-->
> [!tip]
>
> Test AXFR on all discovered internal names
>
> <!-- Example {{{-->
> > [!example]-
> >
> > Test `AXFR` on
> > - `app.inlanefreight.htb`
> > - `dev.inlanefreight.htb`
> > - `internal.inlanefreight.htb`
> > - etc.
> >
> > ```sh
> > dig @$target inlanefreight.htb AXFR
> > ```
> >
> > ```sh
> > ; <<>> DiG 9.20.11-4+b1-Debian <<>> @10.129.44.19 inlanefreight.htb AXFR
> > ; (1 server found)
> > ;; global options: +cmd
> > inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
> > inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
> > inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
> > inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
> > inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
> > app.inlanefreight.htb.  604800  IN      A       10.129.18.15
> > dev.inlanefreight.htb.  604800  IN      A       10.12.0.1
> > internal.inlanefreight.htb. 604800 IN   A       10.129.1.6
> > mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
> > ns.inlanefreight.htb.   604800  IN      A       127.0.0.1
> > inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
> > ;; Query time: 204 msec
> > ;; SERVER: 10.129.44.19#53(10.129.44.19) (TCP)
> > ;; WHEN: Thu Dec 18 20:53:31 EST 2025
> > ;; XFR size: 11 records (messages 1, bytes 560)
> > ```
> <!-- }}} -->
<!-- }}} -->

**MANUAL**

[[Dig#AXFR|Dig]] — Request AXFR Zone Transfer

1. Enumerate [[Networking/Services/DNS/General#Name Server|Name Server(s)]]

```sh
dig <target_domain> NS
```

<!-- Example {{{-->
> [!example]-
>
> Query the
> [zonetransfer.me](https://digi.ninja/projects/zonetransferme.php)
> domain for [[Networking/Services/DNS/General#NS|NS]] records
>
> ```sh
> dig zonetransfer.me NS +short
> ```
> ```sh
> nsztm1.digi.ninja.
> nsztm2.digi.ninja.
> ```
<!-- }}} -->

2. Attempt [[Networking/Services/DNS/General#DNS Zone Transfer|DNS Zone Transfer]] against each
[[Networking/Services/DNS/General#Name Server|Name Server]]

```sh
dig @$target <target_domain> AXFR
```

<!-- Example {{{-->
> [!example]-
>
> Request a full [[Networking/Services/DNS/General#DNS Zone Transfer|DNS Zone Transfer]]
> from the [[Networking/Services/DNS/General#Name Server|Name server(s)]] responsible for the
> [zonetransfer.me](https://digi.ninja/projects/zonetransferme.php)
> domain
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

**AUTOMATE**

[[fierce]] — Automate zone transfers and perform dictionary attacks

```sh
fierce --domain <target_domain> --dns-servers $target
```

[[DNSRecon]] — Automate zone transfers

```sh
dnsrecon -d <target_domain> -t axfr
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> dnsrecon -d zonetransfer.me -t axfr
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Local Query {{{-->
### Local Query

Query `localhost` for records

> [!todo]
>
> Validate commands

```sh
dig @<dns_ip> -x 127.0.0.1
```

```sh
dig @<dns_ip> -x 127.0.0.2
```
<!-- }}} -->

<!-- MX Query {{{-->
### MX Query

Enumerate [[DNS/General#MX|MX]] records

```sh
dig [@<dns_ip>] <target_domain> mx
```

```sh
dig [@<dns_ip>] <target_domain> mx | grep "MX" | grep -v ";"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> dig microsoft.com mx | grep "MX" | grep -v ";"
> ```
> ```sh
> microsoft.com.          3301    IN      MX      10 microsoft-com.mail.protection.outlook.com.
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Automated Tools {{{-->
## Automated Tools

> [!todo]

___
<!-- }}} -->
