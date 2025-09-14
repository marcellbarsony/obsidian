---
id: ELF
aliases:
  - Executable and Linkable Format
  - Exucutable File Format
tags:
  - Linux/General/Files
links: "[[Files-Directories]]"
---

# ELF - Executable and Linkable Format

Executable File Format (formerly Extensible Linking Format) is a standard file
format for [executable](https://en.wikipedia.org/wiki/Executable) files, object
code, [shared libraries](https://en.wikipedia.org/wiki/Library_(computing)) and
[core dumps](https://en.wikipedia.org/wiki/Core_dump).

## File layout

Each ELF file is made up of one ELF header, followed by file data. The data can
include:
- **Program header table**, describing zero or more memory segments
- **Section header table**, describing zero or more sections
- **Data** referred to by entries in the program header table or section header
  table

### Segments

Segments contain information that is needed for
[run time](https://en.wikipedia.org/wiki/Run_time_(program_lifecycle_phase))
execution of the file.

### Sections

Sections contain data for linking and relocation.

## ELF Header

The ELF file header is a structure that contains the metadata of the file. It
defines whether to use 32- or 64-bit addresses.

## Resources

- [IBM](https://www.ibm.com/docs/en/ztpf/1.1.0.14?topic=linkage-executable-linking-format-elf)
- [Linux Audit](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/)
- [LinuxFundataion refspecs - elf.pdf](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [LinuxHint](https://linuxhint.com/understanding_elf_file_format/)
- [man7](https://man7.org/linux/man-pages/man5/elf.5.html)
- [OSDev Wiki](https://wiki.osdev.org/ELF)
- [Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
