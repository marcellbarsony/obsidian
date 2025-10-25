---
id: Rsync
aliases: []
tags:
  - Networking/Services/Rsync/Usage
links: "[[Services]]"
---

# Usage

<!-- Rsync {{{-->
## Rsync

<!-- Connect {{{-->
### Connect

Connect to an Rsync server with the [rsync command](https://linux.die.net/man/1/rsync)

```sh
rsync rsync://<user>@<target>/
```

> [!tip]
>
> The URL format is `[rsync://][user@]host[:port]/module`

___

<!-- }}} -->

<!-- File Operations {{{-->
### File Operations

<!-- Copy {{{-->
#### Copy

Copy a local file/folder to the target

```sh
rsync -av </home/user/dir/> rsync://<user>@<target>/<home/user/dir>
```

Copy a remote file/folder from the target

```sh
rsync -av rsync://<user>@<target>/<home/user/dir> </home/user/dir/>
```

#### SSH

Copy a local file/folder to the target over [[SSH/General|SSH]]

```sh
rsync -av -e ssh </home/user/dir/> <user>@<target>:</home/user/dir/>
```

Copy a remote file/folder from the target over [[SSH/General|SSH]]

```sh
rsync -av -e ssh <user>@<target>:</home/user/dir/> </home/user/dir/>
```

<!-- }}} -->

<!-- Synchronize {{{-->
#### Synchronize

Sync all files from the target

```sh
rsync -av rsync://<target>/<dir>
```

#### SSH

Sync all files from the target through [[SSH/General|SSH]]

```sh
rsync -av rsync://127.0.0.1/dev -e ssh
```

Sync all files from the target through [[SSH/General|SSH]] with custom port

```sh
rsync -av rsync://127.0.0.1/dev -e "ssh -p2222"
```

> [!info]-
>
> [How to Transfer Files with Rsync over SSH](https://phoenixnap.com/kb/how-to-rsync-over-ssh)

<!-- }}} -->

___

<!-- }}} -->

<!-- }}} -->

<!-- R-Commands {{{-->
## R-Commands

[R-Commands](https://en.wikipedia.org/wiki/Berkeley_r-commands)

<!-- Login {{{-->
### Login

[rlogin](https://www.ibm.com/docs/en/aix/7.1.0?topic=r-rlogin-command)
— Log in to a server (*`TCP/513`*)

```sh
rlogin <target> -l <user>
```

> [!example]-
>
> ```sh
> rlogin 10.0.17.2 -l htb-student
> ```
> ```sh
> Last login: Fri Dec  2 16:11:21 from localhost
> ```

<!-- }}} -->

<!-- Execute {{{-->
### Execute

[rsh](https://www.ibm.com/docs/en/zos/3.1.0?topic=srrrib-rsh-commandexecute-command-remote-host-receive-results-your-local-host)
— Execute shell commands on a remote host without login procedure (*`TCP/514`*)

```sh
rsh <target> <command>
```

<!-- }}} -->

<!-- Users {{{-->
### Users

[rwho](https://www.ibm.com/docs/en/aix/7.1.0?topic=r-rwho-command)
— Show logged in users (*`UDP/513`*)

```sh
rwho -a
```

> [!example]-
>
> ```sh
> rwho -a
> ```
> ```sh
> root     web01:pts/0 Dec  2 21:34
> htb-student     workstn01:tty1  Dec  2 19:57  2:25
> ```
>
> - `-a`: Includes all users. Without this flag,
> users whose sessions are idle an hour or more
> are not included in the report.

[rusers]()
— List authenticated users

```sh
rusers -al <target>
```

> [!example]-
>
> ```sh
> rusers -al 10.0.17.5
> ```
> ```sh
> htb-student     10.0.17.5:console          Dec 2 19:57     2:25
> ```

<!-- }}} -->

<!-- System {{{-->
### System

`rstat`
— Show remote system performance statistics from the kernel

```sh
rstat <target>
```

[ruptime](https://linux.die.net/man/1/ruptime)
— Show uptime of all systems in a network

```sh
ruptime
```

<!-- }}} -->

<!-- File Operations {{{-->
### File Operations

[rcp](https://www.ibm.com/docs/en/aix/7.2.0?topic=r-rcp-command)
— Copy a file/directory between local and remote systems with

Copy local file/directory to remote host

```sh
rcp <local_file> <target>:<dir>
```

> [!example]-
>
> ```sh
> rcp localfile host2:/home/eng/jane
> ```

Copy remote file/directory to local host

```sh
rcp <target>:<file> <local_file>
```

> [!example]-
>
> ```sh
> rcp host2:/home/eng/jane/file localfile
> ```


Copy remote file/directory to another remote host

```sh
rcp <target_1>:<file> <target_2>:<file>
```

> [!example]-
>
> ```sh
> rcp host1:/home/eng/jane/newplan host2:/home/eng/mary
> ```
<!-- }}} -->

___

<!-- }}} -->
