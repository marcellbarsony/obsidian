---
id: Performance
aliases: []
tags:
  - Networking/Tools/Nmap/Performance
---

# Performance

Scanning performance plays a significant role
when an extensive network need to be scanned
or dealing with low network bandwidth.

___

<!-- Timeouts {{{-->
## Timeouts

[Round-Trip Time](https://en.wikipedia.org/wiki/Round-trip_delay)
or
[Round-Trip Delay](https://en.wikipedia.org/wiki/Round-trip_delay)
(*default: `--min-RTT-timeout 100`*)
is the amount of time it takes for a signal to be sent
plus the amount of time it takes for acknowledgement of that signal
having been received.


Default scan (*Top 100 ports*)

```sh
sudo nmap <target> -F
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap 10.129.2.0/24 -F
> ```
>
> ```sh
> <SNIP>
> Nmap done: 256 IP addresses (10 hosts up) scanned in 39.44 seconds
> ```
<!-- }}} -->

Optimized RTT (*Round-Trip Time*)


> [!warning]
>
> Setting initial RTT timeout (*`--initial-rtt-timeout`*) too low
> may result in overlooking hosts

```sh
sudo nmap <target> -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
> ```
> ```sh
> <SNIP>
> Nmap done: 256 IP addresses (8 hosts up) scanned in 12.29 seconds
> ```
>
> > [!warning]
> >
> > The scan has found two hosts less with the optimized scan.
> > The initial RTT timeout (*`--initial-rtt-timeout`*) is too short.
<!-- }}} -->

> [!info]-
>
> - `-F`: Scan top 100 ports
> - `--initial-rtt-timeout 50ms`: Set initial RTT timeout
> - `--max-rtt-timeout 100ms`: Set maximum RTT timeout

___
<!-- }}} -->

<!-- Retries {{{-->
## Retries

Specify the retry rate of sent packets (default: `10`)

```sh
sudo nmap 10.129.2.0/24 -F | grep "/tcp" | wc -l
```

Reduced retries (`0`)

```sh
sudo nmap 10.129.2.0/24 -F --max-retries 0 | grep "/tcp" | wc -l
```

> [!info]-
>
> - `-F`: Scan top 100 ports
> - `--max-retries 0`: Set number of retries

___
<!-- }}} -->

<!-- Rates {{{-->
## Rates

Set minimum rate to simultaneously send the specified number of packets

Default scan

```sh
sudo nmap 10.129.2.0/24 -F -oN tnet.default
```

Optimized scan

```sh
sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
```

> [!info]-
>
> - `-F`: Scan top 100 ports
> - `-oN tnet.minrate300`: Saves the results in normal formats
> - `--min-rate 300`: Set the minimum number of packets sent per second

___
<!-- }}} -->

<!-- Timing {{{-->
## Timing

Nmap offers 6 different timing templates to determine
the aggressiveness of the scan as security systems may block
the produced network traffic

> [!info]- Timing Types
>
> - `-T 0` / `-T paranoid`
> - `-T 1` / `-T sneaky`
> - `-T 2` / `-T polite`
> - `-T 3` / `-T normal`
> - `-T 4` / `-T aggressive`
> - `-T 5` / `-T insane`

Default scan

```sh
sudo nmap 10.129.2.0/24 -F -oN tnet.default 
```

Insane scan

```sh
sudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T 5
```

> [!info]-
>
> - `-F`: Scans top 100 ports
> - `-oN tnet.T5`: Saves the results in normal formats
> - `-T 5`: Specify the insane timing template

___
<!-- }}} -->
