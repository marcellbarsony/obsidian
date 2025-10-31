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

Analyze [[DNS/General#DNS Records|DNS records]] to identify
[[DNS/General#Subdomain|Subdomains]],
mail servers, and other infrastructure

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
