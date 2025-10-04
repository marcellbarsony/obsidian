---
id: FHS
aliases:
  - Filesystem Hierarchy Standard
tags:
  - Linux/General/Filesystem/Directories
links: "[[Filesystem]]"
---

# Filesystem Hierarchy Standard

The **Filesystem Hierarchy Standard** ([FHS](https://en.wikipedia.org/wiki/Filesystem_Hierarchy_Standard))
defines the directory structure and directory contents in Linux distributions.

> [!example]-
>
>| Path   | Description |
>| ------ | ----------------------------------------------- |
>| /      | The top-level directory is the root filesystem and contains all of the files required to boot the operating system before other filesystems are mounted, as well as the files required to boot the other filesystems. After boot, all of the other filesystems are mounted at standard mount points as subdirectories of the root. |
>| /bin   | Contains essential command binaries. |
>| /boot  | Consists of the static bootloader, kernel executable, and files required to boot the Linux OS. |
>| /dev   | Contains device files to facilitate access to every hardware device attached to the system. |
>| /etc   | Local system configuration files. Configuration files for installed applications may be saved here as well. |
>| /home  | Each user on the system has a subdirectory here for storage. |
>| /lib   | Shared library files that are required for system boot. |
>| /media | External removable media devices such as USB drives are mounted here. |
>| /mnt   | Temporary mount point for regular filesystems. |
>| /opt   | Optional files such as third-party tools can be saved here. |
>| /root  | The home directory for the root user. |
>| /sbin  | This directory contains executables used for system administration (binary system files). |
>| /tmp   | The operating system and many programs use this directory to store temporary files. This directory is generally cleared upon system boot and may be deleted at other times without any warning. |
>| /usr   | Contains executables, libraries, man files, etc. |
>| /var   | This directory contains variable data files such as log files, email in-boxes, web application related files, cron files, and more. |

> [!example]-
>
>| Directory        | Description                                                                                                                                                                                                                                                                                                          |
>| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
>| **/**            | Primary hierarchy root - Root directory of the entire file system hierarchy                                                                                                                                                                                                                                          |
>| **/bin**         | Command binaries that need to be available in [single-user mode](https://en.wikipedia.org/wiki/Single-user_mode) (e.g., `cat`, `ls`, `cp`)                                                                                                                                                                           |
>| **/boot**        | Bootloader files.                                                                                                                                                                                                                                                                                                    |
>| **/dev**         | Device files (e.g., `/dev/null`, `/dev/disk0`, `/dev/sda1`, `/dev/tty`, `/dev/random`)                                                                                                                                                                                                                               |
>| **/etc**         | Host-specific system-wide configuration files.                                                                                                                                                                                                                                                                       |
>| /etc/opt         | Configuration files for add-on packages stored in `/opt`.                                                                                                                                                                                                                                                            |
>| /etc/sgml        | Configuration files, such as catalogs for software that processes [SGML](https://en.wikipedia.org/wiki/Standard_Generalized_Markup_Language)                                                                                                                                                                         |
>| /etc/X11         | Configuration files for the X Window System version 11.                                                                                                                                                                                                                                                              |
>| /etc/xml         | Configuration files for for software that processes XML.                                                                                                                                                                                                                                                             |
>| **/home**        | User's home directories, containing saved files, personal settings, etc.                                                                                                                                                                                                                                             |
>| **/lib**         | Libraries essential for the binaries in `/bin` and `/sbin`.                                                                                                                                                                                                                                                          |
>| /lib`<qial>`     | Alternate format essential libraries.                                                                                                                                                                                                                                                                                |
>| /media           | Mount points for removable media.                                                                                                                                                                                                                                                                                    |
>| **/mnt**         | Temporary mounted filesystem.                                                                                                                                                                                                                                                                                        |
>| **/opt**         | Add-on application software packages.                                                                                                                                                                                                                                                                                |
>| **/proc**        | Virtual filesystem providing process and kernel information as files.                                                                                                                                                                                                                                                |
>| **/root**        | Home directory for the root user.                                                                                                                                                                                                                                                                                    |
>| **/run**         | Runtime variable data: information about the running system since last boot (e.g., logged-in users, running daemons).                                                                                                                                                                                                |
>| **/sbin**        | Essential system binaries.                                                                                                                                                                                                                                                                                           |
>| **/srv**         | Site-specific data served by this system, such as data and scrips for web servers, data offered by FTP servers, and repositories for version control systems.                                                                                                                                                        |
>| **/tmp**         | Temporary files (see also `/var/tmp`).                                                                                                                                                                                                                                                                               |
>| **/usr**         | Secondary hierarchy for read-only user data; (multi-)user utilities and applications.                                                                                                                                                                                                                                |
>| /usr/bin         | Non-essential command binaries (not needed in single-user mode) for all users.                                                                                                                                                                                                                                       |
>| /usr/include     | Standard [include files](https://en.wikipedia.org/wiki/Include_directive).                                                                                                                                                                                                                                           |
>| /usr/lib         | Libraries for the binaries in `/usr/bin` and `/usr/sbin`.                                                                                                                                                                                                                                                            |
>| /usr/lib`<qual>` | Alternative-format libraries (e.g., `/usr/lib32` for 32-bit libraries on a 64-bit machine).                                                                                                                                                                                                                          |
>| /usr/local       | Tertiary hierarchy for local data, specific to this host. Typically has further subdirectories (e.g., `bin`, `lib`, `share`).                                                                                                                                                                                        |
>| /usr/sbin        | Non-essential system binaries (e.g. daemons for various network services).                                                                                                                                                                                                                                           |
>| /usr/share       | Architecture-independent (shared) date.                                                                                                                                                                                                                                                                              |
>| **/var**         | Variable files: files where the content of the file is expected to continually change during normal operation of the system (e.g., logs, spool files, etc.).                                                                                                                                                         |
>| /var/cache       | Application cached data. Such data are locally generated as a result of time-consuming I/O or calculation.                                                                                                                                                                                                           |
>| /var/lib         | State information. Persistent data modified by programs as they run (e.g., databases, packaging system metadata, etc.).                                                                                                                                                                                              |
>| /var/lock        | Lock files. Files keeping track of resources currently in use.                                                                                                                                                                                                                                                       |
>| /var/log         | Various log files.                                                                                                                                                                                                                                                                                                   |
>| /var/mail        | Mailbox files.                                                                                                                                                                                                                                                                                                       |
>| /var/opt         | Variable data from add-on packages that are stored in `/opt`.                                                                                                                                                                                                                                                        |
>| /var/run         | Run-time variable data. This directory contains system information data describing the system since it was booted. In FHS 3.0, `/var/run` is replaced by `/run`; a system should either continue to provide a `/var/run` directory or provide a symbolic link from `/var/run` to `/run` for backwards compatibility. |
>| /var/spool       | [Spool](https://en.wikipedia.org/wiki/Spooling) for tasks waiting to be processed (e.g., print queues, outgoing e-mail queue).                                                                                                                                                                                       |
>| /var/tmp         | Temporary files to be preserved between reboots.                                                                                                                                                                                                                                                                     |


## FHS Compliance

Most Linux distributions follow the **Filesystem Hierarchy Standard** and
declare it their own policy to maintain FHS compliance.
