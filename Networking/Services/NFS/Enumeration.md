---
id: Enumeration
aliases:
  - Network File System
tags:
  - Networking/Services/NFS/Enumeration
links: "[[Services]]"
---

# Enumeration

<!-- Nmap {{{-->
## Nmap

Enumerate TCP ports `111` and `2049`

```sh
sudo nmap -sC -sV <target_ip> -p111,2049
```

### Nmap scripts

The `rpcinfo` NSE script retrieves a list of running RPC services.
This checks whether the target share is connected to the network on all required
ports.

```sh
sudo nmap --script nfs* <target_ip> -sV -p111,2049
```

> [!tip]
>
> Useful Nmap scripts
>
> ```sh
> nfs-ls        # List NFS exports and check permissions
> nfs-showmount # Like showmount -e
> nfs-statfs    # Disk statistics and NFS share info
> ```
<!-- }}} -->

<!-- Discover & Mount {{{-->
## Discover & Mount

### Show NFS Shares

Ask the **NFS server** (the RPC mount daemon) what directories it is exporting
and to which clients

> [!example]-
>
> ```sh
> showmount -e <target_ip>
> ```

### Mount NFS Shares

Mount remote **NFS shares** to the local machine

1. Create a mount directory

> [!example]-
>
> ```sh
> mkdir target-NFS
> ```

2. Mount the NFS share(s)

```sh
sudo mount -t nfs [-o vers=2] <target_ip>:<remote_folder> <local_folder> -o nolock
```

> [!example]-
>
> ```sh
> sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
> ```
>
> > [!info]-
> >
> > - `mount`: Mount a filesystem to the Linux directory tree
> > - `-t nfs`: Specify the filesystem type ([[General|NFS]])
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
> > - `-t nfs`: Specify the filesystem type ([[General|NFS]])
> > - `[-o vers=2]`: Force NFSv2 (compatibility instead of v3 or v4)
> > - `10.12.0.150:/backup`: NFS server IP and export path (directory)
> > - `./mnt/new_back/`: Local mount point
> > - `-o nolock`: Mount option (disable file locking)

3. Change to the mount directory and show content

> [!example]-
>
> ```sh
> cd target-NFS
> tree .
> ```
<!-- }}} -->

<!-- Unmount {{{-->
## Unmount

Unmount the remote **NFS** share from the local machine

```sh
sudo umount ./target-NFS
```
<!-- }}} -->

<!-- Metasploit {{{-->
## Metasploit

1. [[Metasploit#Launch Metasploit|Launch Metasploit]]


2. [[Metasploit#Search Exploit|Search ]] for some useful modules

```sh
search nfs
```

3. [[Metasploit#Select Exploit|Select]] the the scanner

Scan NFS mounts and list permissions

```sh
use scanner/nfs/nfsmount
```

4. [[Metasploit#Show Options|Show options]]

5. [[Metasploit#Set Options|Set options]]

6. [[Metasploit#Check Exploit|Check Module]]

7. [[Metasploit#Run Exploit|Run Module]]

<!-- }}} -->
