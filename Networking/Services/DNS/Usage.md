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

Perform default (`A` [[General#DNS Records|record]]) lookup for the domain

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

Retrieves the IPv4 address (`A` [[General#DNS Records|record]])
associated with the domain

```sh
dig domain.com A
```

Retrieve the IPv6 address (`AAAA` [[General#DNS Records|record]])
associated with the domain

```sh
dig domain.com AAAA
```

Find the mail servers (`MX` [[General#DNS Records|record]])
responsible for the domain

```sh
dig domain.com MX
```

Retriever text (`TXT` [[General#DNS Records|record]])
associated with the domain

```sh
dig domain.com TXT
```

Identify the
[[General#Authoritative Name Server|Authoritative Name Servers]]
for the domain

```sh
dig domain.com NS
```

Retrieves the canonical name (`CNAME` [[General#DNS Records|record]])
for the domain

```sh
dig domain.com CNAME
```

Retrieves the start of authority (`SOA` [[General#DNS Records|record]])
for the domain

```sh
dig domain.com SOA
```

Specifies a specific name server to query

```sh
dig @1.1.1.1 domain.com
```

Show the full path of DNS resolution

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

Retrieves all available DNS records (`ANY`) for the domain

> [!warning]
>
> Many DNS servers ignore `ANY` queries to reduce load
> and prevent abuse ([RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482))

```sh
dig domain.com ANY
```
<!-- }}} -->

___
<!-- }}} -->
