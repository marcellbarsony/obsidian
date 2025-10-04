---
id: cURL
aliases:
  - "cURL"
tags:
  - Linux/General/Tools/cURL
links: "[[Tools]]"
---

# cURL

[cURL](https://curl.se/) is an open-source CLI app for uploading and downloading
individual files.

## Usage

```sh
curl [Options] <url>
```

### Options

| Options | Description                      |
| ------- | -------------------------------- |
| -d      | POST data                        |
| -H      | Custom header                    |
| -I      | GET Response header              |
| -L      | Redirect                         |
| -o      | Download (specify file name)     |
| -O      | Download (original name)         |
| -v      | Verbose output (TLS handshake)   |

### Flags

| Flags                   | Description      |
| ----------------------- | ---------------- |
| --cookie "key=value"    | Cookie set       |
| --data-binary @-        | POST binary file |
| --data-binary @file.txt | POST binary file |

### Examples
