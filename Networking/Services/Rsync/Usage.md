---
id: Rsync
aliases: []
tags:
  - Networking/Services/Rsync/Usage
links: "[[Services]]"
---

# Usage

<!-- Connect {{{-->
## Connect

Connect to an Rsync server with the [rsync](https://linux.die.net/man/1/rsync)
command

```sh
rsync rsync://<user>@<target>/
```

> [!tip]
>
> The URL format is `[rsync://][user@]host[:port]/module`

___

<!-- }}} -->

<!-- Synchronize {{{-->
## Synchronize

Sync all files from the target

```sh
rsync -av rsync://<target>/<dir>
```

Sync all files from the target through [[SSH/General|SSH]]

> [!example]-
>
> ```sh
> rsync -av rsync://127.0.0.1/dev -e ssh
> ```
>
> ```sh
> rsync -av rsync://127.0.0.1/dev -e "ssh -p2222"
> ```

> [!info]-
>
> [How to Transfer Files with Rsync over SSH](https://phoenixnap.com/kb/how-to-rsync-over-ssh)

___

<!-- }}} -->
