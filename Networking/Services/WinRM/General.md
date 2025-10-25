---
id: General
aliases: "Windows Remote Management"
tags:
  - Networking/Services/WinRM/General
port:
  - 5985/HTTP
  - 5986/HTTPS
---

# General

**WinRM** ([Windows Remote Management](https://en.wikipedia.org/wiki/Windows_Remote_Management))
is a Windows integrated remote management cmd protocol.

**WinRM** uses the SOAP ([Simple Object Access Protocol](https://en.wikipedia.org/wiki/SOAP))
to establish connection, and TCP ports `5985` (*HTTP*) and `5986` (*HTTPS*)
for communication.

WinRS ([Windows Remote Shell](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs)),
allows the execution arbitrary commands (`cmd.exe`) on a remote system.
