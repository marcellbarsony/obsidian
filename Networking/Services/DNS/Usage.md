---
id: DNS
tags:
  - Networking/Services/DNS/Usage
links: "[[Services]]"
---

# Usage

___

<!-- DIG {{{-->
## DIG

**DIG** ([Domain Information Groper](https://en.wikipedia.org/wiki/Dig_(command)))
is a network administration command-line tool for querying
[[General#DNS Structure|DNS servers]]
to retrieve various types of [[General#DNS Records|DNS records]].

<!-- Commands {{{-->
### Commands

Default (`A` [[General#DNS Records|record]]) lookup for the domain

```sh
dig domain.com
```

<!-- Example {{{-->
> [!example]-
>
> <!-- Example {{{-->
> ```sh
> dig google.com
> ```
> ```sh
> ; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
> ;; global options: +cmd
> ;; Got answer:
> ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
> ;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
> ;; WARNING: recursion requested but not available
>
> ;; QUESTION SECTION:
> ;google.com.                    IN      A
>
> ;; ANSWER SECTION:
> google.com.             0       IN      A       142.251.47.142
>
> ;; Query time: 0 msec
> ;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
> ;; WHEN: Thu Jun 13 10:45:58 SAST 2024
> ;; MSG SIZE  rcvd: 54
> ```
> <!-- }}} -->
>
> <!-- Header {{{-->
> > [!info]- Header
> >
> > `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449`
> >
> > - `QUERY`: Type of query
> > - `NOERROR`: Status (*successful*)
> > - `16449`: Unique ID
> >
> > `;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`
> >
> > - `qr`: Query Response flag - *indicates this is a response*
> > - `rd`: Recursion Desired flag - *recursion was requested*
> > - `ad`: Authentic Data flag - *the resolver considers the data authentic*
> > - The remaining numbers indicate the number of entries
> >   in each section of the DNS response:
> >   *1 question, 1 answer, 0 authority records, and 0 additional records*
> >
> > `;; WARNING: recursion requested but not available`
> >
> > - Recursion was requested, but the server does not support it
> <!-- }}} -->
>
> <!-- Question {{{-->
> > [!info]- Question
> >
> > `;google.com. IN A`:
> > "What is the IPv4 address (A record) for `google.com`?"
> <!-- }}} -->
>
> <!-- Answer {{{-->
> > [!info]- Answer
> >
> > - `google.com. 0 IN A 142.251.47.142`:
> > The IP address associated with `google.com` is `142.251.47.142`
> >
> > - `0` represents the TTL (*time-to-live*)
> <!-- }}} -->
>
> <!-- Footer {{{-->
> > [!info]- Footer
> >
> > - `;; Query time: 0 msec`:
> >   Time the query took (*0 ms*)
> > - `;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)`:
> >   This identifies the DNS server that provided the answer
> >   and the protocol used (UDP).
> > - `;; WHEN: Thu Jun 13 10:45:58 SAST 2024`:
> >   This is the timestamp of when the query was made
> > - `;; MSG SIZE rcvd: 54`:
> >   Indicates the size of the DNS message received (*54 bytes*)
> <!-- }}} -->
<!-- }}} -->

IPv4 address ([[General#A|A record]])
associated with the domain

```sh
dig domain.com A
```

IPv6 address ([[General#AAAA|AAAA record]])
associated with the domain

```sh
dig domain.com AAAA
```

All available DNS records
([[General#ANY|ANY record]])
for the domain

```sh
dig domain.com ANY
```

Canonical Name ([[General#CNAME|CNAME record]])
for the domain

```sh
dig domain.com CNAME
```

Mail servers ([[General#MX|MX record]])
responsible for the domain

```sh
dig domain.com MX
```

[[General#Authoritative Name Server|Authoritative Name Servers]]
([[General#NS|NS record]])
for the domain

```sh
dig domain.com NS
```

Start Of Authority ([[General#SOA|SOA record]])
for the domain

```sh
dig domain.com SOA
```

Text records ([[General#TXT|TXT record]])
associated with the domain

```sh
dig domain.com TXT
```

Specify a specific name server to query

```sh
dig @1.1.1.1 domain.com
```

Show the full path of the DNS resolution

```sh
dig +trace domain.com
```

Perform a reverse lookup to find the associated host name

```sh
dig -x 192.168.1.1
```

Provides a short, concise answer to the query

```sh
dig +short domain.com
```

Displays only the answer section of the query output

```sh
dig +noall +answer domain.com
```
<!-- }}} -->

___
<!-- }}} -->

<!-- nslookup {{{-->
## nslookup

> [!warning]
>
> Deprecated

> [!todo]

___
<!-- }}} -->

<!-- Host {{{-->
## Host

Resolve a host name into an IP address or an IP address into a host name

```sh
host [-a] [-c Class ] [-d ] [-r ] [-t Type] [-v ] [-w ] <hostname> | <address> [Server]
```

<!-- Example {{{-->
> [!example]-
>
> Display the IP address of a host named `mephisto`
>
> ```sh
> host mephisto
> ```
> ```sh
> mephisto is 192.100.13.5, Aliases: engr, sarah
> ```
>
> Display the host whose IP address is `192.100.13.1`
>
> ```sh
> host 192.100.13.1
> ```
> ```sh
> mercutio is 192.100.13.1
> ```
>
> Display the [[General#NS]] record
> ```sh
> host -t ns inlanefreight.com
> ```
> ```sh
> ;; communications error to ::1#53: connection refused
> ;; communications error to ::1#53: connection refused
> inlanefreight.com name server ns1.inlanefreight.com.
> inlanefreight.com name server ns2.inlanefreight.com. 
> ```
<!-- }}} -->

___
<!-- }}} -->
