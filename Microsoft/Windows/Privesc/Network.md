---
id: Network
aliases: []
tags:
  - Microsoft/Windows/Privesc/Network
links: Privesc
---

# Network

___

<!-- General {{{-->
## General

Enumerate General Network Information

> [!tip]
>
> - Interfaces (*e.g., dual-homed machine*)
> - IP Address(es)
> - DNS Information

```sh
ipconfig /all
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> ipconfig /all
> ```
> ```sh
> Windows IP Configuration
>
>    Host Name . . . . . . . . . . . . : WINLPE-SRV01
>    Primary Dns Suffix  . . . . . . . :
>    Node Type . . . . . . . . . . . . : Hybrid
>    IP Routing Enabled. . . . . . . . : No
>    WINS Proxy Enabled. . . . . . . . : No
>    DNS Suffix Search List. . . . . . : .htb
>
> Ethernet adapter Ethernet1:
>
>    Connection-specific DNS Suffix  . :
>    Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
>    Physical Address. . . . . . . . . : 00-50-56-B9-C5-4B
>    DHCP Enabled. . . . . . . . . . . : No
>    Autoconfiguration Enabled . . . . : Yes
>    Link-local IPv6 Address . . . . . : fe80::f055:fefd:b1b:9919%9(Preferred)
>    IPv4 Address. . . . . . . . . . . : 192.168.20.56(Preferred)
>    Subnet Mask . . . . . . . . . . . : 255.255.255.0
>    Default Gateway . . . . . . . . . : 192.168.20.1
>    DHCPv6 IAID . . . . . . . . . . . : 151015510
>    DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-27-ED-DB-68-00-50-56-B9-90-94
>    DNS Servers . . . . . . . . . . . : 8.8.8.8
>    NetBIOS over Tcpip. . . . . . . . : Enabled
>
> Ethernet adapter Ethernet0:
>
>    Connection-specific DNS Suffix  . : .htb
>    Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
>    Physical Address. . . . . . . . . : 00-50-56-B9-90-94
>    DHCP Enabled. . . . . . . . . . . : Yes
>    Autoconfiguration Enabled . . . . : Yes
>    IPv6 Address. . . . . . . . . . . : dead:beef::e4db:5ea3:2775:8d4d(Preferred)
>    Link-local IPv6 Address . . . . . : fe80::e4db:5ea3:2775:8d4d%4(Preferred)
>    IPv4 Address. . . . . . . . . . . : 10.129.43.8(Preferred)
>    Subnet Mask . . . . . . . . . . . : 255.255.0.0
>    Lease Obtained. . . . . . . . . . : Thursday, March 25, 2021 9:24:45 AM
>    Lease Expires . . . . . . . . . . : Monday, March 29, 2021 1:28:44 PM
>    Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:4ddf%4
>                                        10.129.0.1
>    DHCP Server . . . . . . . . . . . : 10.129.0.1
>    DHCPv6 IAID . . . . . . . . . . . : 50352214
>    DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-27-ED-DB-68-00-50-56-B9-90-94
>    DNS Servers . . . . . . . . . . . : 1.1.1.1
>                                        8.8.8.8
>    NetBIOS over Tcpip. . . . . . . . : Enabled
>
> Tunnel adapter isatap..htb:
>
>    Media State . . . . . . . . . . . : Media disconnected
>    Connection-specific DNS Suffix  . : .htb
>    Description . . . . . . . . . . . : Microsoft ISATAP Adapter
>    Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
>    DHCP Enabled. . . . . . . . . . . : No
>    Autoconfiguration Enabled . . . . : Yes
>
> Tunnel adapter Teredo Tunneling Pseudo-Interface:
>
>   Media State . . . . . . . . . . . : Media disconnected
>   Connection-specific DNS Suffix  . :
>   Description . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
>   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
>   DHCP Enabled. . . . . . . . . . . : No
>   Autoconfiguration Enabled . . . . : Yes
>
> Tunnel adapter isatap.{02D6F04C-A625-49D1-A85D-4FB454FBB3DB}:
>
>   Media State . . . . . . . . . . . : Media disconnected
>   Connection-specific DNS Suffix  . :
>   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
>   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
>   DHCP Enabled. . . . . . . . . . . : No
>   Autoconfiguration Enabled . . . . : Yes
>```
<!-- }}} -->

<!-- ARP Table {{{-->
### ARP Table

```sh
arp -a
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> arp -a
> ```
> ```sh
> Interface: 10.129.43.8 --- 0x4
>   Internet Address      Physical Address      Type
>   10.129.0.1            00-50-56-b9-4d-df     dynamic
>   10.129.43.12          00-50-56-b9-da-ad     dynamic
>   10.129.43.13          00-50-56-b9-5b-9f     dynamic
>   10.129.255.255        ff-ff-ff-ff-ff-ff     static
>   224.0.0.22            01-00-5e-00-00-16     static
>   224.0.0.252           01-00-5e-00-00-fc     static
>   224.0.0.253           01-00-5e-00-00-fd     static
>   239.255.255.250       01-00-5e-7f-ff-fa     static
>   255.255.255.255       ff-ff-ff-ff-ff-ff     static
>
> Interface: 192.168.20.56 --- 0x9
>   Internet Address      Physical Address      Type
>   192.168.20.255        ff-ff-ff-ff-ff-ff     static
>   224.0.0.22            01-00-5e-00-00-16     static
>   224.0.0.252           01-00-5e-00-00-fc     static
>   239.255.255.250       01-00-5e-7f-ff-fa     static
>   255.255.255.255       ff-ff-ff-ff-ff-ff     static
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Routing Table {{{-->
### Routing Table

```sh
C:\htb> route print
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> route print
> ```
>
> ```sh
> ===========================================================================
> Interface List
>   9...00 50 56 b9 c5 4b ......vmxnet3 Ethernet Adapter
>   4...00 50 56 b9 90 94 ......Intel(R) 82574L Gigabit Network Connection
>   1...........................Software Loopback Interface 1
>   3...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter
>   5...00 00 00 00 00 00 00 e0 Teredo Tunneling Pseudo-Interface
>  13...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #2
> ===========================================================================
>
> IPv4 Route Table
> ===========================================================================
> Active Routes:
> Network Destination        Netmask          Gateway       Interface  Metric
>           0.0.0.0          0.0.0.0       10.129.0.1      10.129.43.8     25
>           0.0.0.0          0.0.0.0     192.168.20.1    192.168.20.56    271
>        10.129.0.0      255.255.0.0         On-link       10.129.43.8    281
>       10.129.43.8  255.255.255.255         On-link       10.129.43.8    281
>    10.129.255.255  255.255.255.255         On-link       10.129.43.8    281
>         127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
>         127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
>   127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
>      192.168.20.0    255.255.255.0         On-link     192.168.20.56    271
>     192.168.20.56  255.255.255.255         On-link     192.168.20.56    271
>    192.168.20.255  255.255.255.255         On-link     192.168.20.56    271
>         224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
>         224.0.0.0        240.0.0.0         On-link       10.129.43.8    281
>         224.0.0.0        240.0.0.0         On-link     192.168.20.56    271
>   255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
>   255.255.255.255  255.255.255.255         On-link       10.129.43.8    281
>   255.255.255.255  255.255.255.255         On-link     192.168.20.56    271
> ===========================================================================
> Persistent Routes:
>   Network Address          Netmask  Gateway Address  Metric
>           0.0.0.0          0.0.0.0     192.168.20.1  Default
> ===========================================================================
>
> IPv6 Route Table
> ===========================================================================
> Active Routes:
>  If Metric Network Destination      Gateway
>   4    281 ::/0                     fe80::250:56ff:feb9:4ddf
>   1    331 ::1/128                  On-link
>   4    281 dead:beef::/64           On-link
>   4    281 dead:beef::e4db:5ea3:2775:8d4d/128
>                                     On-link
>   4    281 fe80::/64                On-link
>   9    271 fe80::/64                On-link
>   4    281 fe80::e4db:5ea3:2775:8d4d/128
>                                     On-link
>   9    271 fe80::f055:fefd:b1b:9919/128
>                                     On-link
>   1    331 ff00::/8                 On-link
>   4    281 ff00::/8                 On-link
>   9    271 ff00::/8                 On-link
> ===========================================================================
> Persistent Routes:
>   None
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- Internet Settings {{{-->
## Internet Settings

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

```powershell
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

<!-- }}} -->
