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

[WHOIS](https://en.wikipedia.org/wiki/WHOIS)
returns domain registration information —
it is a query and response protocol used for querying databases that store
information about registered internet resources

```sh
whois <target>
```

<!-- Example {{{-->
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
<!-- }}} -->

<!-- Info {{{-->
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
<!-- }}} -->

___
<!-- }}} -->

<!-- DNS {{{-->
## DNS

Analyze DNS records to identify subdomains, mail servers,
and other infrastructure

<!-- Tip {{{-->
> [!tip]-
>
> CMD tools
>
> - [[DNS/Usage#DIG|dig]]
> - [[DNS/Usage#nslookup|nslookup]]
> - [[DNS/Usage#Host|Host]]
>
> Other tools
>
> - [[Fierce]]
> - [[dnsrecon]]
<!-- }}} -->

___
<!-- }}} -->

<!-- SSL Certificate {{{-->
## SSL Certificate

<!-- Certificate Transparency {{{-->
### Certificate Transparency

[Certificate Transparency](https://en.wikipedia.org/wiki/Certificate_Transparency)
([RFC-6962](https://datatracker.ietf.org/doc/html/rfc6962))
is a process intended to enable the verification of issued digital certificates
for encrypted Internet connections

> [!tip]
>
> **Certificate Transparency logs**
> may expose subdomains, which might host outdated software
> or configurations
>
> - [crt.sh](https://crt.sh)
> - [Censys](https://search.censys.io/)

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

___
<!-- }}} -->

<!-- }}} -->
