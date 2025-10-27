---
id: Performance
aliases: []
tags:
  - Networking/Tools/Nmap/Performance
---

# Performance

___

<!-- Timeouts {{{-->
## Timeouts

Default scan

```sh
sudo nmap 10.129.2.0/24 -F
```

Optimized RTT (Round-Trip-Time)

```sh
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

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

Nmap offers 6 different timing templates to determine the aggressiveness of the
scan - security systems may block the produced network traffic

> [!example]-
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
