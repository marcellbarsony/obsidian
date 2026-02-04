---
id: theHarvester
aliases: []
tags:
  - Webapp/Enumeration/Tools/theHarvester
links: "[[Webapp/Enumeration/General|General]]"
---

# theHarvester

[theHarvester](https://github.com/laramies/theHarvester)

___

<!-- Options {{{-->
## Options

> [!todo]

```sh
-v, --virtual-host    Verify host name via DNS resolution and search for virtual hosts.
-r, --dns-resolve [DNS_RESOLVE]
                      Perform DNS resolution on subdomains with a resolver list or passed in resolvers, default False.
-n, --dns-lookup      Enable DNS server lookup, default False.
-c, --dns-brute       Perform a DNS brute force on the domain.
-f, --filename FILENAME
                      Save the results to an XML and JSON file.
-w, --wordlist WORDLISTe, --dns-server      DNS_SERVER
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

```sh
theHarvester -d <domain> -b <source>
```

> [!info]
>
> - `-d <domain>`:
> - `-b <source>`:

Verbose mode

```sh
theHarvester -d <domain> -b <source> -l 100 -v
```

Save results to a file

```sh
theharvester -d example.com -b yahoo,bing -f results
```

___
<!-- }}} -->
