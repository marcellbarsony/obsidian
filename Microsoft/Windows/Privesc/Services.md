---
id: Services
aliases:
  - Services
tags:
  - Microsoft/Windows/Services
links: "[[Windows]]"
---

# Services

___

<!-- Identify {{{-->
## Identify

Identify currently running services

[net](https://en.wikipedia.org/wiki/Net_(command)) —
List running services

```sh
net start
```

[wmic](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) —
List running services (*compact*)

```sh
wmic service list brief
```

[sc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11)) —
Query the status of services

```sh
sc query
```

[Get-Service](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-7.5) —
List and manage services

```powershell
Get-Service
```

<!-- Network Services {{{-->
### Network Services

Enumerate active local network services

<!-- Tip {{{-->
> [!tip]-
>
> Look for entries
>
> - Listening on loopback addresses (*`127.0.0.1` and `::1`*)
> - Not listening on the machine's local IP
> - Not listening on the broadcast address (*`0.0.0.0`, `::/0`*)
<!-- }}} -->

[netstat](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) —
List active TCP and UDP connections and ports listening

```sh
netstat -ano
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> PS C:\htb> netstat -ano
> ```
>
> ```sh
> Active Connections
>
>   Proto  Local Address          Foreign Address        State           PID
>   TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1096
>   TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
>   TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       840
>   TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
>   TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3520
>   TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       968
> <...SNIP...>
>  ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Permissions {{{-->
## Permissions

Permissions of a service

```sh
sc qc <service_name>
```

[accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) —
Check required privilege level for each service

```sh
accesschk.exe -ucqv <service_name>
```

Check if "Authenticated Users" can modify any service

```sh
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```
```sh
accesschk.exe -uwcqv %USERNAME% * /accepteula
```
```sh
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
```
```sh
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

<!-- Weak Permissions {{{-->
#### Weak Permissions

Check if n modify the binary that is executed by a service or if you have write permissions on the folder where the binary is located (DLL Hijacking).

You can get every binary that is executed by a service using wmic (not in system32) and check your permissions using icacls:

```sh
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt
```

```sh
for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Use `sc` and `icacls`

```sh
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
```

```sh
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
```

```sh
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Service Triggers {{{-->
## Service Triggers

Privileged services can be started without `SERVICE_START` rights
by firing their **Service Triggers**

> [!info]- Service Triggers
>
> **Service Triggers** let Windows start a service when certain conditions occur
> (*e.g., named pipe/RPC endpoint activity, ETW events, IP availability,
> device arrival, GPO refresh, etc.*)

> [!info]- Resources
>
> - [HackTricks](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/service-triggers.html)

> [!todo]

___
<!-- }}} -->

<!-- Service Management {{{-->
### Service Management

<!-- Enable {{{-->
#### Enable

Enable services when the following error occurs
(*e.g., with SSDPSRV*)

<!-- Warning {{{-->
> [!warning]
>
> ```sh
> System error 1058 has occurred.
> The service cannot be started, either because it is disabled
> or because it has no enabled devices associated with it.
> ```
<!-- }}} -->

```sh
sc config SSDPSRV start= demand
```

```sh
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

```sh
sc.exe config usosvc start= auto
```

<!-- }}} -->

### Restart

```sh
wmic service NAMEOFSERVICE call startservice
```

```sh
net stop [service name] && net start [service name]
```

> [!tip]-
>
> Privileges can be escalated through various permissions:
>
> - `SERVICE_CHANGE_CONFIG`: Allows reconfiguration of the service binary.
> - `WRITE_DAC`: Enables permission reconfiguration, leading to the ability
>    to change service configurations.
> - `WRITE_OWNER`: Permits ownership acquisition and permission reconfiguration.
> - `GENERIC_WRITE`: Inherits the ability to change service configurations.
> - `GENERIC_ALL`: Also inherits the ability to change service configurations.
>
> For the detection and exploitation of this vulnerability,
> the exploit/windows/local/service_permissions can be utilized.

___
<!-- }}} -->
