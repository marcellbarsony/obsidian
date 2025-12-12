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

Show drive letters

```sh
wmic logicaldisk get caption || fsutil fsinfo drives
```

List logical disks with drive letter, description and provider name
(*network drives*)

```sh
wmic logicaldisk get caption,description,providername
```

Show PowerShell filesystem drives with names and root paths

```powershell
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
