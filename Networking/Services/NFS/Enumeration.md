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

Useful Nmap scripts

```sh
nfs-ls        # List NFS exports and check permissions
nfs-showmount # Like showmount -e
nfs-statfs    # Disk statistics and NFS share info
```
<!-- }}} -->

<!-- Discover & Mount {{{-->
## Discover & Mount

### Show NFS Shares

Ask the **NFS** server (the RPC mount daemon) what directories it is exporting
and to which clients

```sh
showmount -e <target_ip>
```

### Mount NFS Shares

Mount remote **NFS** shares to the local machine

1. Create a mount directory

```sh
mkdir target-NFS
```

2. Mount the NFS share(s)

```sh
sudo mount -t nfs [-o vers=2] <target_ip>:<remote_folder> <local_folder> -o nolock

# Example
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
sudo mount -t nfs [-o vers=2] 10.12.0.150:/backup /mnt/new_back -o nolock
```

3. Change to the mount directory and show content

```sh
cd target-NFS
tree .
```
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

1. Launch the Metasploit framework

```sh
msfconfsole
```

2. Select some useful modules

```sh
use scanner/nfs/nfsmount # Scan NFS mounts and list permissions
```

3. Configure target `RHOST` (and other options)
<!-- }}} -->
