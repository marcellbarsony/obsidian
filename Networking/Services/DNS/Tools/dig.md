---
id: dig
tags:
  - Networking/Services/DNS/Tools/dig
links: "[[Services]]"
---

# DIG

**DIG** ([Domain Information Groper](https://en.wikipedia.org/wiki/Dig_(command)))
is a network administration command-line tool for querying
[[General#DNS Structure|DNS servers]]
to retrieve various types of [[General#DNS Records|DNS records]].

___

<!-- Records {{{-->
## Records

### A

IPv4 address ([[General#A|A record]])
associated with the domain

```sh
dig <domain.com>
```

```sh
dig <domain.com> A
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

### AAAA

IPv6 address ([[General#AAAA|AAAA record]])
associated with the domain

```sh
dig <domain.com> AAAA
```

### ANY

All available DNS records
([[General#ANY|ANY record]])
for the domain

```sh
dig <domain.com> ANY
```

### AXFR

Request a zone transfer

```sh
dig <domain.com> AXFR
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

### CNAME

Canonical Name ([[General#CNAME|CNAME record]])
for the domain

```sh
dig <domain.com> CNAME
```

### MX

Mail servers ([[General#MX|MX record]])
responsible for the domain

```sh
dig <domain.com> MX
```

### NS

[[General#Authoritative Name Server|Authoritative Name Servers]]
([[General#NS|NS record]])
for the domain

```sh
dig <domain.com> NS
```

### SOA

Start Of Authority ([[General#SOA|SOA record]])
for the domain

```sh
dig <domain.com> SOA
```

### TXT

Text records ([[General#TXT|TXT record]])
associated with the domain

```sh
dig <domain.com> TXT
```
<!-- }}} -->

<!-- Options {{{-->
## Options

### Trace

Show the full path of the DNS resolution

```sh
dig +trace <domain.com>
```

### Short

Provides a short, concise answer to the query

```sh
dig +short <domain.com>
```

### Answer Only

Displays only the answer section of the query output

```sh
dig +noall +answer <domain.com>
```
<!-- }}} -->

## BIND Version Info

Grab banner and [BIND](https://en.wikipedia.org/wiki/BIND)
server version

```sh
dig @<dns_ip> version.bind CHAOS TXT
```

## Specify Nameserver

Specify a specific name server to query

```sh
dig @1.1.1.1 <domain.com>
```

## Reverse Lookup

Perform a reverse lookup to find the associated host name

```sh
dig -x 192.168.1.1
```

___
<!-- }}} -->
