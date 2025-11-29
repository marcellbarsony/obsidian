---
id: cURL
aliases:
  - cURL
tags:
  - Linux/General/Tools/cURL
links: "[[Linux/General/Tools/Tools]]"
---

# cURL

[cURL](https://curl.se/) is an open-source CLI app
for uploading and downloading individual files

___

<!-- Usage {{{-->
## Usage

Synopsis

```sh
curl [Options] <url>
```
___
<!-- }}} -->

<!-- Options {{{-->
## Options

Most common options

<!-- Example {{{-->
> [!example]-
>
> | Options | Description                      |
> | ------- | -------------------------------- |
> | -d      | POST data                        |
> | -H      | Custom header                    |
> | -I      | GET Response header              |
> | -L      | Redirect                         |
> | -o      | Download (specify file name)     |
> | -O      | Download (original name)         |
> | -v      | Verbose output (TLS handshake)   |
<!-- }}} -->

___
<!-- }}} -->

<!-- Flags {{{-->
## Flags

Most common flags

<!-- Example {{{-->
> [!example]-
>
> | Flags                   | Description      |
> | ----------------------- | ---------------- |
> | --cookie "key=value"    | Cookie set       |
> | --data-binary @-        | POST binary file |
> | --data-binary @file.txt | POST binary file |
<!-- }}} -->

___
<!-- }}} -->
