---
id: Exposed Credentials
aliases: []
tags:
  - Microsoft/Windows/Privesc/Exposed-Credentials
links: Privesc
---

# Exposed Credentials

Look for exposed credentials in configuration files, log files,
and user history files

Search for patterns like `username`, `password`, `key`, `secret`, etc

___

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

Check is enable in the registry

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

```powershell
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
```

```powershell
Stop-Transcript
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Credential Manager {{{-->
## Credential Manager

Windows stores credentials in **Credential Manager**,
which may store usernames, passwords, and other authentication information

### CMD

```cmd
cmdkey
```

### PowerShell

[Get-Credential - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-credential)

```powershell
Get-Credential
```

### Control Panel

1. Open `Control Panel`
2. `User Accounts`
3. `Credential Manager`

<!-- }}} -->

<!-- Application Configuration Files {{{-->
## Application Configuration Files

Applications may store credentials in configuration files

<!-- INI Files {{{-->
### INI Files

```cmd
C:\ProgramData\<AppName>\config.ini
```
```sh
C:\Users\<User>\AppData\Local\<AppName>\appsettings.ini
```
<!-- }}} -->

<!-- CONF Files {{{-->
### CONF Files

```cmd
C:\ProgramData\<AppName>\config.conf
```
```cmd
C:\Users\<User>\AppData\Local\<AppName>\config.conf
```
<!-- }}} -->

<!-- XML Files {{{-->
### XML Files

Web servers or database apps use XML files to store data

```cmd
C:\Program Files\<AppName>\config.xml
```
<!-- }}} -->

<!-- JSON Files {{{-->
### JSON Files

Web apps and other softwar often use JSON configuration files

```cmd
C:\Users\<User>\AppData\Local\<AppName>\settings.json
```
<!-- }}} -->

<!-- YAML/Env Files {{{-->
### YAML/Env Files

Some application (e.g. Docker, Kubernetes) store configuragions in YAML or
environment variable files

```cmd
C:\Users\<User>\.docker\config.json
```
```
C:\Users\<User>\AppData\Local\<AppName>\config.yaml
```
<!-- }}} -->
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

<!-- }}} -->
