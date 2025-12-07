---
id: File System
aliases: []
tags:
  - Microsoft/Windows/Privesc/File-System
links: Privesc
---

# File System

___

## Drives

```powershell
wmic logicaldisk get caption || fsutil fsinfo drives
```

```powershell
wmic logicaldisk get caption,description,providername
```

```powershell
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
