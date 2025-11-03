---
id: Host Discovery
aliases: []
tags:
  - Networking/Enumeration/Host_Discovery
---

# Host Discovery

Identify which hosts are up on a network

Once the hosts are identified, 

<!-- ARP Discovery {{{-->
## ARP Discovery

<!-- netdiscover {{{-->
### netdiscover

Active scan all private ranges
(*i.e. `192.168.0.0/16`, `172.16.0.0/12`, `10.0.0.0/8`*)

```sh
netdiscover -i $INTERFACE
```

Active scan a range (*e.g. 192.168.0.0/24*)

```sh
netdiscover -i $INTERFACE -r $RANGE
```

Passive scan (*doesn't send packets*)

```sh
netdiscover -i $INTERFACE -p
```

<!-- }}} -->

<!-- p0f {{{-->
### p0f

> [!todo]

<!-- }}} -->

<!-- bettercap {{{-->
### bettercap

> [!todo]

<!-- }}} -->

___
<!-- }}} -->

<!-- NBT Discovery {{{-->
## NBT Discovery

**NBT Discovery** sends [[NetBIOS/General|NetBIOS]] status query
to each address in supplied range and lists received information

### nbtscan

[nbtscan](https://github.com/resurrecting-open-source-projects/nbtscan)
— Scan networks searching for [[NetBIOS/General|NetBIOS]] information

```sh
nbtscan -r <network_range>
```

___
<!-- }}} -->

## ICMP Echo Discovery

> [!warning]
>
> This scanning method works only if the firewalls of the hosts allow it

Send one echo request to a host

- **Windows**: `ping -n 1 <host>`
- **UNIX**: `ping -c 1 <host>`
