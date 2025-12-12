---
id: Credential Hunting
aliases: []
tags:
  - Microsoft/Windows/Privesc/Credential-Hunting
links: Privesc
---

# Credentials Hunting

Look for exposed credentials in configuration files,
log files, and user history files

Search for [[Secrets]] like `username`, `password`, `key`, `secret`, etc.

___

<!-- Application Configuration Files {{{-->
## Application Configuration Files

Applications may store credentials in configuration files

- INI Files

```cmd
C:\ProgramData\<AppName>\config.ini
```

```sh
C:\Users\<User>\AppData\Local\<AppName>\appsettings.ini
```

- CONF Files

```cmd
C:\ProgramData\<AppName>\config.conf
```

```cmd
C:\Users\<User>\AppData\Local\<AppName>\config.conf
```

- XML Files - Web servers or database apps use `XML` files to store data

```cmd
C:\Program Files\<AppName>\config.xml
```

- JSON Files - Web apps and other softwar often use `JSON` configuration files

```cmd
C:\Users\<User>\AppData\Local\<AppName>\settings.json
```

- YAML/Env Files - Application (*e.g. Docker, Kubernetes*)
store configurations in `YAML`, `JSON`, or environment variable files

```cmd
C:\Users\<User>\.docker\config.json
```

```
C:\Users\<User>\AppData\Local\<AppName>\config.yaml
```
<!-- }}} -->

<!-- Clipboard {{{-->
## Clipboard

Enumerate the contents of the clipboard for credentials

[Get-Clipboard](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-clipboard?view=powershell-7.5) —
Gets the content of the clipboard

```cmd
powershell -command "Get-Clipboard"
```

```powershell
Get-Clipboard
```

___
<!-- }}} -->

<!-- Credential Manager {{{-->
## Credential Manager

Windows stores credentials in **Credential Manager**,
which may store usernames, passwords, and other authentication information

[cmdkey](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) —
Creates, lists, and deletes stored user names and passwords or credentials

```cmd
cmdkey
```

[Get-Credential](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-credential) —
Gets a credential object based on a user name and password

```powershell
Get-Credential
```

Control Panel

1. Open `Control Panel`
2. `User Accounts`
3. `Credential Manager`

___
<!-- }}} -->

<!-- Environment Variables {{{-->
## Environment Variables

Enumerate environment variables for credentials

```powershell
set
```
```powershell
dir env:
```
```powershell
Get-ChildItem Env: | ft Key,Value -AutoSize
```
___
<!-- }}} -->

<!-- Memory Mining {{{-->
## Memory Mining

[procdump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) —
Create a memory dump of a running process

> [!tip]
>
> Services like [[FTP/General|FTP]] store their credentials
> in clear text in memory

1. [[Processes#Identify|Identify]] the process name

```sh
tasklist
```

2. Dump the memory of the process

```sh
procdump.exe -accepteula -ma <proc_name>
```

<!-- Example {{{-->
> [!example]-
>
> 1. Identify the process name
>
> ```sh
> tasklist
> ```
>
> ```sh
> notepad.exe              3456
> chrome.exe               8124
> powershell.exe           6500
> ```
>
> 2. Dump the memory of the process based on its name
>
> ```sh
> procdump.exe -accepteula -ma notepad.exe
> ```
<!-- }}} -->

<!-- }}} -->

<!-- PowerShell {{{-->
## PowerShell

<!-- History {{{-->
### History

Find history path

```powershell
ConsoleHost_history
```

Enumerate `ConsoleHost_history.txt` for exposed credentials

```powershell
C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```powershell
Get-Content "C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
```

```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```powershell
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```powershell
cat (Get-PSReadlineOption).HistorySavePath
```

```powershell
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

Automate search with PowerShell

```powershell
Select-String -Pattern "user|password|key|secret|flag|htb" "C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
```

<!-- }}} -->

<!-- Logs {{{-->
### Logs

**PowerShell Logs** may store details about executed commands

```cmd
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
```
<!-- }}} -->

<!-- Profile {{{-->
### Profile

A custom **PowerShell Profile** may be used to store configuration settings

```cmd
C:\Users\<User>\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
```
<!-- }}} -->

<!-- Transcript Files {{{-->
#### Transcript Files

Check if enabled in the [[Registry]]

```powershell
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
```

```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
```

```powershell
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
```

```powershell
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
```

```powershell
dir C:\Transcripts
```

Start a Transcription session

[Start-Transcript](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript?view=powershell-7.5) —
Creates a record of all or part of a PowerShell session to a text file

```powershell
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
```

```powershell
Stop-Transcript
```

<!-- }}} -->

___
<!-- }}} -->
