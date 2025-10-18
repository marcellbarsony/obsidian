---
id: Enumeration
aliases:
  - Network File System
tags:
  - Networking/Services/NFS/Enumeration
links: "[[Services]]"
---

# Enumeration

<!-- Checklist {{{-->
## Checklist

- [ ] [[#Nmap|Nmap]]
- [ ] [[#Discover & Mount|Discover & Mount]]
    - [ ] [[#Show NFS Shares|Show NFS Shares]]
    - [ ] [[#Mount NFS Shares|Mount NFS Shares]]
- [ ] [[#Metasploit| Metasploit Scan]]

___

<!-- }}} -->

<!-- Nmap {{{-->
## Nmap

Detect NFS services and identify server capabilities

```sh
nmap -p 2049,111 <target> -oA nfs-default
```

Enumerate TCP ports `111` and `2049`

```sh
sudo nmap -sC -sV <target> -p 111,2049 -oA nfs-default-scripts
```

<!-- Info {{{-->
> [!info]-
>
> `-sC`: Run the [rpcinfo](https://nmap.org/nsedoc/scripts/rpcinfo.html
> script to retrieve a list of running RPC services.
> This checks whether the target share is connected to the network on all required
> ports.
<!-- }}} -->

Run all nfs scripts (
[nfs-ls](https://nmap.org/nsedoc/scripts/nfs-ls.html),
[nfs-showmount](https://nmap.org/nsedoc/scripts/nfs-showmount.html),
[nfs-statfs](https://nmap.org/nsedoc/scripts/nfs-statfs.html)
)

```sh
sudo nmap --script nfs* <target> -sV -p111,2049 -oA nfs-rpc-detection
```

<!-- CVE Scripts {{{-->
### CVE Scripts

[[Exploitation#CVE-2010-4344|CVE-2010-4344]] (
[smtp-vuln-cve2010-4344](https://nmap.org/nsedoc/scripts/smtp-vuln-cve2010-4344.html)
)

```sh
sudo nmap -sV --script=smtp-vuln-cve2010-4344 -p 25,465,587 <target> -oA smtp-vuln-cve2010-4344
```

[[Exploitation#CVE-2011-1720|CVE-2011-1720]] (
[smtp-vuln-cve2011-1720](https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1720.html)
)

```sh
sudo nmap -sV --script=smtp-vuln-cve2011-1720 -p 25,465,587 <target> -oA smtp-vuln-cve2011-1720
```

[[Exploitation#CVE-2011-1764|CVE-2011-1764]] (
[smtp-vuln-cve2010-1764](https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1764.html)
)

```sh
sudo nmap -sV --script=smtp-vuln-cve2011-1764 -p 25,465,587 <target> -oA smtp-vuln-cve2011-1764
```

<!-- }}} -->

___

<!-- }}} -->

<!-- Discover & Mount {{{-->
## Discover & Mount

<!-- Show NFS Shares {{{-->
### Show NFS Shares

Ask the **NFS server** (*the RPC mount daemon*) what directories it is exporting
and to which clients

<!-- Example {{{-->
> [!example]-
>
> ```sh
> showmount -e <target>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Mount NFS Shares {{{-->
### Mount NFS Shares

Mount remote **NFS shares** to the local machine

1. Create a mount directory

<!-- Example {{{-->
> [!example]-
>
> ```sh
> mkdir target-NFS
> ```
<!-- }}} -->

2. Mount the NFS share(s)

```sh
sudo mount -t nfs [-o vers=2] <target>:<remote_folder> <local_folder> -o nolock
```

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
<!-- }}} -->

3. Change to the mount directory and show content

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cd target-NFS
> tree .
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Unmount NFS Shares {{{-->
## Unmount NFS Shares

Unmount the remote **NFS** share from the local machine

```sh
sudo umount ./target-NFS
```

<!-- }}} -->

___

<!-- }}} -->

<!-- Metasploit {{{-->
## Metasploit

Scan NFS mounts and list permissions with [[Metasploit]]

```sh
use scanner/nfs/nfsmount
```

<!-- Example {{{-->
> [!example]-
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
