---
id: Boot-Process
aliases: []
tags:
  - Linux/General/Boot/Boot-Process
---

# Boot Process

In order to [boot Arch Linux](https://wiki.archlinux.org/title/Arch_boot_process),
a Linux-capable [bootloader](https://wiki.archlinux.org/title/Arch_boot_process#Boot_loader)
must be set up. The bootloader is responsible for loading the kernel and
[initial ramdisk](https://wiki.archlinux.org/title/Arch_boot_process#initramfs)
before initiating the boot process.

## System Startup / Hardware Initialization

### BIOS

**[BIOS](https://en.wikipedia.org/wiki/BIOS)** is the very first program
([firmware](https://en.wikipedia.org/wiki/Firmware)) that is executed once the
system is switched on. In most cases it is stored in flash memory in the
motherboard itself and independent of the system storage.

1. System switched on

2. POST ([power-on self-test](https://en.wikipedia.org/wiki/Power-on_self-test))
  executed

3. BIOS launches the first 440 bytes (the
  [MBR bootstrap code area](<https://wiki.archlinux.org/title/Partitioning#Master_Boot_Record_(bootstrap_code)>))
  of the disk in the BIOS disk order

4. The bootloader's first stage in the MBR boot code then launches its second
  stage code (if any) from either:

- Next disk sectors after the MBR, I.e. the so called post-MBR gap (only on a
  MBR partition table)

- A partition's or a partitionless disk's volume boot record ([VBR](https://en.wikipedia.org/wiki/Volume_boot_record))

- The [BIOS boot partition](<https://wiki.archlinux.org/title/GRUB#GUID_Partition_Table_(GPT)_specific_instructions>)
  (GRUB on a BIOS/GPT only)

5. The actual bootloader is launched

6. The bootloader then loads an operating system by either chain-loading or
  directly loading the operating system kernel.

### UEFI

The **UEFI** ([Unified Extensible Firmware Interface](https://en.wikipedia.org/wiki/UEFI))
has support for reading both the [GUID partition table](https://en.wikipedia.org/wiki/GUID_Partition_Table)
as well as file systems. **UEFI*8 doesn't launch any boot code from the [MBR](https://wiki.archlinux.org/title/Partitioning#Master_Boot_Record_(bootstrap_code))
whether it exists or not, instead booting relies on boot entries in the [NVRAM](https://en.wikipedia.org/wiki/Non-volatile_random-access_memory).

1. System switched on

2. POST ([power-on self-test](https://en.wikipedia.org/wiki/Power-on_self-test))
  executed

3. UEFI initializes the hardware required for booting (e.g., *disk*, *keyboard*
  *controllers*, *etc*.)

4. Firmware reads the boot entries in the NVRAM to determine which EFI
  application to launch and from where. (e.g. from which disk partition)

- A boot entry could simply be a disk. In this case the firmware look for an
  EFI system partition on that disk and tries to find an EFI application in the
  fallback boot path (`\EFI\BOOT\BOOTx64.EFI`)

5. Firmware launches the EFI application

- This could be a bootloader ([GRUB](https://wiki.archlinux.org/title/GRUB))
  or the Arch kernel itself using [EFISTUB](https://wiki.archlinux.org/title/EFISTUB)

- It could be some other EFI application such as a UEFI shell or a boot manager
  like systemd-boot

If Secure Boot is enabled, the boot process will verify authenticity of the EFI
binary by signature

## Boot Stages

### Bootloader

A [bootloader](https://en.wikipedia.org/wiki/Bootloader) is a piece of software
started by the firmware (BIOS or UEFI). It is responsible for loading the kernel
with the wanted [kernel parameters](https://wiki.archlinux.org/title/Kernel_parameters),
and initial RAM disk ([mkinitcpio](https://wiki.archlinux.org/title/Mkinitcpio))
based on configuration files.

In the case of **UEFI**, the kernel itself can be directly launched by the
**UEFI** using the EFI boot stub ([EFISTUB](https://wiki.archlinux.org/title/EFISTUB)).

A separate bootloader or boot manager can still be used for the purpose of
editing kernel parameters before booting.

> [!warning]
>
> A bootloader must be able to access the kernel and initramfs image(s),
> otherwise the system will not boot. Thus, in a typical setup, it must support
> accessing `/boot`.

### Kernel

The [kernel](https://wiki.archlinux.org/title/Kernel) is the core of an operating system.
It functions on a low level (kernelspace) interacting between the hardware of the machine and the programs which use the hardware to run.

The kernel temporarily stops programs to run other programs in the meantime, which is known as [preemption](<https://en.wikipedia.org/wiki/Preemption_(computing)>).
This creates the illusion of many tasks being executed simultaneously, even on single-core CPUs.
The kernel uses the CPU scheduler to decide which program takes priority at any given moment.

### Initramfs

After the bootloader loads the kernel and possible initramfs files and executes
the kernel, the kernel unpacks the initramfs (initial RAM filesystem) archives
to the (then empty) rootfs (initial root filesystem, specifically a ramfs or
tmpfs). The first extracted initramfs is the one embedded in the kernel binary
during the kernel build, then possible external initramfs files are extracted.
This files in the external initramfs overwrite files with the same name in the
embedded initramfs. The kernel then executes `/init` (in the rootfs) as the
first process. The early userspace starts.

Arch Linux official kernels use an empty archive for the built-in initramfs
(which is the default when building Linux). External initramfs images can be
generated with mkinitcpio, dracut or booster.

The purpose of initramfs is to bootstrap the system to the point where it can
access the root filesystem (see [FHS](<https://wiki.archlinux.org/title/Frequently_asked_questions#Does_Arch_follow_the_Linux_Foundation's_Filesystem_Hierarchy_Standard_(FHS)?>)
for details). This means that any modules that are required for devices like IDE,
SCSI, SATA, USB/FW (if booting from an external drive) must be loadable from the
initramfs if not built into the kernel; once the proper modules are loaded
(either explicitly via a program or script, or implicitly via udev), the boot
process continues. For this reason, the initramfs only needs to contain the
modules necessary to access the root filesystem; it does not need to contain
every module one would ever want to use. The majority of modules will be loaded
later on by [udev](https://wiki.archlinux.org/title/Udev), during the init
process.

### Init process

At the final stage of the early userspace, the real root is mounted, and then
replaces the initial root filesystem. `/sbin/init` is executed, replacing the
`/init` process.

> [!info]
>
> Arch uses [**systemd**](https://wiki.archlinux.org/title/Systemd) as the
> default init

### Getty

init calls getty once for each virtual terminal (typically 6 of them), which
initializes each TTY and asks for a username and password. Once provided, getty
checks them against `/etc/passwd` and `/etc/shadow`, then calls login.

Alternatively, getty may start a display manager if one is present on the
system.

### Display Manager (optional)

A display manager can be configured to replace the getty login prompt on a tty.

In order to automatically initialize a display manager after booting, it is
necessary to manually enable the service unit through systemd.

### Login

The login program beings a session for the user by setting environment variables
and starting the user's shell, based on `/etc/passwd`.

The login program displays the contents of `/etc/motd`
([message of the day](<https://en.wikipedia.org/wiki/Motd_(Unix)>)) after a
successful login, just before it executes the login shell. It is a good place
to display your Terms of Service to remind users of your local policies or
anything you wish you tell them.

### Shell

Once the user's shell is started, it will typically run a runtime configuration
file, such as [bashrc](https://wiki.archlinux.org/title/Bash#Configuration_files),
before presenting a prompt to the user. If the account is configured to Start X
at login, the runtime configuration will call `startx` or `xinit`.

### GUI

[Xinit](https://wiki.archlinux.org/title/Xinit) (or
[Wayland](https://wiki.archlinux.org/title/wayland)) runs the user's
[xinitrc](https://wiki.archlinux.org/title/Xinit#xinitrc) runtime configuration
file, which normally starts a window manager. When the user is finished and
exits the window manager, xinit, startx, the shell, and login will terminate in
that order, returning to getty.
