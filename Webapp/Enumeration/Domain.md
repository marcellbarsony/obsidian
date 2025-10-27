---
id: Domain
aliases: []
tags:
  - Webapp/Enumeration/Passive/Domain
---

# Domain

___

<!-- WHOIS {{{-->
## WHOIS

[WHOIS](https://en.wikipedia.org/wiki/WHOIS) is a query and response protocol
used for querying databases that store information about retistered internet
resources

```sh
whois <target>
```

> [!example]-
>
> ```sh
> whois inlanefreight.com
> ```
> ```sh
> [...]
> Domain Name: inlanefreight.com
> Registry Domain ID: 2420436757_DOMAIN_COM-VRSN
> Registrar WHOIS Server: whois.registrar.amazon
> Registrar URL: https://registrar.amazon.com
> Updated Date: 2023-07-03T01:11:15Z
> Creation Date: 2019-08-05T22:43:09Z
> [...]
> ```

> [!info]-
>
> Each WHOIS record typically contains the following information
>
> - **Domain Name**: The domain name itself (*e.g., example.com*)
> - **Registrar**: The company where the domain was registered (*e.g., GoDaddy, Namecheap*)
> - **Registrant Contact**: The person or organization that registered the domain
> - **Administrative Contact**: The person responsible for managing the domain
> - **Technical Contact**: The person handling technical issues related to the domain
> - **Creation and Expiration Dates**: Domain registration and expiration date
> - **[[DNS/General#DNS Structure|Name Server]]**: Servers that translate the domain name into an IP address

___
<!-- }}} -->

<!-- DNS {{{-->
## DNS

> [!todo]

Analyse DNS records to identify subdomains, mail servers, and other infrastructure.

Using dig to enumerate subdomains of a target domain.

dig, nslookup, host, dnsenum, fierce, dnsrecon

### Subdomains

#### Brute Force

Brute Force with [[Gobuster#DNS Subdomain Enumeration|Gobuster]]

```sh
gobuster dns <flags> -d <target> -w <wordlist.txt>
```

Brute Force with [[DNSEnum]]

```sh
dnsenum --enum <target> -f <wordlist.txt> -r
```

#### DNS Zone Transfer

> [!todo]

___
<!-- }}} -->

<!-- SSL Certificate {{{-->
## SSL Certificate

<!-- Certificate Transparency {{{-->
### Certificate Transparency

[Certificate Transparency](https://en.wikipedia.org/wiki/Certificate_Transparency)
([RFC-6962](https://datatracker.ietf.org/doc/html/rfc6962))
is a process intended to enable the verification of issued digital certificates
for encrypted Internet connections. This is intended to enable
the detection of false or maliciously issued certificates for a domain

> [!tip]
>
> [Inspect](https://crt.sh) the SSL certificates, as
> **Certificate Transparency** logs may expose subdomains

List SSL certificates

```sh
curl -s https://crt.sh/\?q\=<example.com>\&output\=json | jq .
```

> [!info]-
>
> - `-s`: Silent mode, suppress progress bars and error messages

Filter SSL certificate by unique subdomains

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
}}}

___
<!-- }}} -->
