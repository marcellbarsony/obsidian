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
List services

```powershell
Get-Service
```


[Get-Service](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-7.5) —
List services (*filter by name*)

```sh
Get-Service | ? {$_.DisplayName -like '<service>*'}
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> PS C:\htb> get-service | ? {$_.DisplayName -like 'Druva*'}
> ```
>
> ```sh
> Status   Name               DisplayName
> ------   ----               -----------
> Running  inSyncCPHService   Druva inSync Client Service
> ```
<!-- }}} -->

<!-- Network Services {{{-->
### Network Services

Enumerate active local network services

- Listening on loopback addresses (*`127.0.0.1` and `::1`*)
- Not listening on the machine's local IP
- Not listening on the broadcast address (*`0.0.0.0`, `::/0`*)

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

[netstat](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) —
List active TCP and UDP connections on a specific port

```sh
netstat -ano | findstr 6064
```

[tasklist](https://en.wikipedia.org/wiki/Tasklist) —
Correlate found service `PID` with the service name

```sh
tasklist | findstr /c:"<pid>"
```

[Get-Process](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.5) —
Map the process PID back to the running process

```sh
get-process -Id <pid>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> PS C:\htb> get-process -Id 3324
> ```
>
> ```sh
> Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
> -------  ------    -----      -----     ------     --  -- -----------
>     149      10     1512       6748              3324   0 inSyncCPHwnet64
> ```
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

Check if it's possible to  modify the binary that is executed by a service
or the folder is writable where the binary is located
(*[[DLL Hijacking]]*)

1. Extract executable paths of binaries executed by a service

```sh
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt
```

2. Check permissions

```sh
for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Use `sc` and `icacls`

1. Extract all service names to a file to `Servicenames.txt`

```sh
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
```

2. Extract the service names to `services.txt`

```sh
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
```

3. Retrieve each service's executable path to `path.txt`

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
## Service Management

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
