---
id: Environment
aliases: []
tags:
  - Microsoft/Windows/Privesc/Environment
links: Privesc
---

# Environment Enumeration

___

<!-- Environment Variables {{{-->
## Environment Variables

Enumerate all environment variables

```sh
set
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> set
> ```
>
> ```sh
> ALLUSERSPROFILE=C:\ProgramData
> APPDATA=C:\Users\Administrator\AppData\Roaming
> CommonProgramFiles=C:\Program Files\Common Files
> CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
> CommonProgramW6432=C:\Program Files\Common Files
> COMPUTERNAME=WINLPE-SRV01
> ComSpec=C:\Windows\system32\cmd.exe
> HOMEDRIVE=C:
> HOMEPATH=\Users\Administrator
> LOCALAPPDATA=C:\Users\Administrator\AppData\Local
> LOGONSERVER=\\WINLPE-SRV01
> NUMBER_OF_PROCESSORS=6
> OS=Windows_NT
> Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;
> PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
> PROCESSOR_ARCHITECTURE=AMD64
> PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
> PROCESSOR_LEVEL=23
> PROCESSOR_REVISION=3100
> ProgramData=C:\ProgramData
> ProgramFiles=C:\Program Files
> ProgramFiles(x86)=C:\Program Files (x86)
> ProgramW6432=C:\Program Files
> PROMPT=$P$G
> PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
> PUBLIC=C:\Users\Public
> SESSIONNAME=Console
> SystemDrive=C:
> SystemRoot=C:\Windows
> TEMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
> TMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
> USERDOMAIN=WINLPE-SRV01
> USERDOMAIN_ROAMINGPROFILE=WINLPE-SRV01
> USERNAME=Administrator
> USERPROFILE=C:\Users\Administrator
> windir=C:\Windows 
> ```
<!-- }}} -->

___
<!-- }}} -->
