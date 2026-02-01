---
id: Enumeration
aliases:
  - Network File System
tags:
  - Networking/Services/NFS/Enumeration
links: "[[Services]]"
---

# Enumeration

___

<!-- Service Scan {{{-->
## Service

[[Nmap]] — Detect NFS services and identify server capabilities

```sh
nmap $target -p 2049,111 -oA nfs-default
```

[[Nmap]] — Enumerate TCP ports `111` and `2049`

```sh
sudo nmap -sC -sV $target -p 111,2049 -oA nfs-default-scripts
```

<!-- Info {{{-->
> [!info]-
>
> `-sC`: Run the [rpcinfo](https://nmap.org/nsedoc/scripts/rpcinfo.html
> script to retrieve a list of running RPC services.
> This checks whether the target share is connected to the network on all required
> ports.
<!-- }}} -->

[[Nmap]] — Run all nfs scripts
(*[nfs-ls](https://nmap.org/nsedoc/scripts/nfs-ls.html),
[nfs-showmount](https://nmap.org/nsedoc/scripts/nfs-showmount.html),
[nfs-statfs](https://nmap.org/nsedoc/scripts/nfs-statfs.html)*)

```sh
sudo nmap -sV $target -p 111,2049 --script nfs* -oA nfs-rpc-detection
```

[[Metasploit]] — [NFS Mount Scanner](https://www.rapid7.com/db/modules/auxiliary/scanner/nfs/nfsmount/)

```sh
use scanner/nfs/nfsmount
```

<!-- Example {{{-->
> [!example]-
>
> Scan NFS mounts and list permissions
>
> 1. [[Metasploit#Launch Metasploit|Launch Metasploit]]
>
> 2. [[Metasploit#Search Exploit|Search ]] for some useful modules
>
> ```sh
> search nfs
> ```
>
> 3. [[Metasploit#Select Exploit|Select]] the the scanner
>
> ```sh
> use scanner/nfs/nfsmount
> ```
>
> 4. [[Metasploit#Show Options|Show options]]
>
> 5. [[Metasploit#Set Options|Set options]]
>
> 6. [[Metasploit#Check Exploit|Check Module]]
>
> 7. [[Metasploit#Run Exploit|Run Module]]
<!-- }}} -->

___

<!-- }}} -->

<!-- Discover & Mount {{{-->
## Discover & Mount

<!-- Show NFS Shares {{{-->
### Show NFS Shares

Ask the **NFS server** (*the RPC mount daemon*) what directories it is exporting
and to which clients

```sh
showmount -e $target
```

<!-- }}} -->

<!-- Mount NFS Shares {{{-->
### Mount NFS Shares

Mount remote **NFS shares** to the local machine

1. Create a mount directory

```sh
sudo mkdir /mnt/target-NFS
```

2. Mount the NFS share(s)

```sh
sudo mount -t nfs [-o vers=2] $target:<remote_folder> <local_folder> -o nolock
```

```sh
sudo mount -t nfs $target:/ /mnt/target-NFS -o nolock
```

> [!info]-
>
> - `-o`: `vers=2`, `vers=3`
> - `proto=tcp`
> - `nfs4_disable_idmapping`

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
> ```
>
> > [!info]-
> >
> > - `mount`: Mount a filesystem to the Linux directory tree
> > - `-t nfs`: Specify the filesystem type ([[Networking/Services/NFS/General|NFS]])
> > - `10.129.14.128:/`: NFS server IP and export path (directory)
> > - `./target-NFS/`: Local mount point
> > - `-o nolock`: Mount option (disable file locking)
>
> ```sh
> sudo mount -t nfs [-o vers=2] 10.12.0.150:/backup /mnt/new_back -o nolock
> ```
>
> > [!info]-
> >
> > - `mount`: Mount a filesystem to the Linux directory tree
> > - `-t nfs`: Specify the filesystem type ([[Networking/Services/NFS/General|NFS]])
> > - `[-o vers=2]`: Force NFSv2 (compatibility instead of v3 or v4)
> > - `10.12.0.150:/backup`: NFS server IP and export path (directory)
> > - `./mnt/new_back/`: Local mount point
> > - `-o nolock`: Mount option (disable file locking)
<!-- }}} -->

3. Check for [[Networking/Services/NFS/General#Default Configuration|Root Squashing]]

```sh
ls -ld /mnt/target-NFS
```

> [!example]-
>
> The NFS export applies `root_squash`
>
> ```sh
> ls -ld /mnt/target-NFS
> ```
> ```sh
> drwx------ 2 nobody nogroup 65536 Nov 10  2021 target-NFS
> ```

```sh
sudo mount -t nfs $target:/TechSupport ./target-NFS -o nolock,uid=$(id -u nobody),gid=$(getent group nogroup | cut -d: -f3)
```

Remount the NFS share with the correct `uid`/`gid`

```sh
sudo umount target-NFS
```

```sh
sudo mount -t nfs $target:/TechSupport ./target-NFS -o nolock,uid=65534,gid=65534
```

> [!todo]

> [!resources]
>
> [vk9-sec.com](https://vk9-sec.com/2049-tcp-nfs-enumeration/)

4. Change to the mount directory and show content

```sh
cd target-NFS
```

```sh
tree .
```

```sh
ls -lah
```

<!-- Permission Denied {{{-->
> [!warning]- Permission Denied
>
> Try to elevate user privileges on `Permission Denied`
> error
>
> ```sh
> sudo su
> ```
>
> Or list the contents as `sudo`
>
> ```sh
> sudo ls -lA target-NFS/
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Unmount NFS Shares {{{-->
### Unmount NFS Shares

Unmount the remote **NFS** share from the local machine

```sh
sudo umount ./target-NFS
```

<!-- }}} -->

___

<!-- }}} -->
