---
id: Exposed Credentials
aliases: []
tags:
  - Microsoft/Windows/Privesc/Exposed-Credentials
---

# Exposed Credentials

Look for exposed credentials in configuration files, log files, and user history
files.

Search for patterns like `username`, `password`, `key`, `secret`.

<!-- PowerShell {{{-->
## PowerShell

### PowerShell Profile

A custom PowerShell profile may be used to store configuration settings

```cmd
C:\Users\<User>\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
```

### PowerShell Logs

PowerShell logs may store details about executed commands

```cmd
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
```

### PSReadLine

**PSReadLine** is a module in PowerShell that manages the command-line editing
experience (e.g., command history, input editing) within PowerShell sessions.

Check `ConsoleHost_history.txt` for exposed credentials

```cmd
C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Inspect `ConsoleHost_history.txt` with PowerShell

```powershell
Get-Content "C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
```

Automate search with PowerShell

```powershell
Select-String -Pattern "user|password|key|secret" "C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
```
<!-- }}} -->

<!-- Credential Manager {{{-->
## Credential Manager

Windows stores credentials in Credential Manager which may store usernames,
passwords, and other authentication information.

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

### INI Files

```cmd
C:\ProgramData\<AppName>\config.ini
C:\Users\<User>\AppData\Local\<AppName>\appsettings.ini
```

### CONF Files

```cmd
C:\ProgramData\<AppName>\config.conf
C:\Users\<User>\AppData\Local\<AppName>\config.conf
```

### XML Files

Web servers or database apps use XML files to store data

```cmd
C:\Program Files\<AppName>\config.xml
```

### JSON Files

Web apps and other softwar often use JSON configuration files

```cmd
C:\Users\<User>\AppData\Local\<AppName>\settings.json
```

### YAML/Env Files

Some application (e.g. Docker, Kubernetes) store configuragions in YAML or
environment variable files

```cmd
C:\Users\<User>\.docker\config.json
C:\Users\<User>\AppData\Local\<AppName>\config.yaml
```

<!-- }}} -->
