---
id: General
aliases:
  - Remote Desktop Protocol
tags:
  - Networking/Services/RDP/General
port:
  - 3389
---

# RDP

**RDP** (*[Remote Desktop Protocol](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol)*)
is a proprietary protocol developed by Microsoft
for encrypted IP remote access

For an **RDP** session to be established, both the network firewall
and the firewall on the server must allow connections from the outside

**RDP** is using
[TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security)
or
[RDP Security](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8e8b2cca-c1fa-456c-8ecb-a82fc60b2322)
for encryption

The **Remote Desktop service** is installed by default
on Windows servers

___

<!-- Network Level Authentication {{{-->
## Network Level Authentication

**Network Level Authentication**
([NLA](https://en.wikipedia.org/wiki/Remote_Desktop_Services#Network_Level_Authentication))
is an RDP feature that requires the connecting user to authenticate
before the session is established

___
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

<!-- Enable {{{-->
### Enable

Enable RDP Service on Windows with `Administrator` privileges

<!-- Example {{{-->
> [!example]-
>
> ```sh
> Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
> ```
>
> ```sh
> Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
