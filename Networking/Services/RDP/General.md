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

## Configuration

### Enable

Enable RDP Service on Windows with `Administrator` privileges

> [!example]-
>
> ```sh
> Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
> ```
>
> ```sh
> Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
> ```
