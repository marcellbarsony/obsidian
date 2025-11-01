---
id: WhatWeb
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Tools/WhatWeb
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# WhatWeb

[WhatWeb](https://whatweb.net/) ([GitHub](https://github.com/urbanadventurer/WhatWeb))
extracts the version of the web server,
supporting frameworks, applications, and CMS

<!-- Usage {{{-->
## Usage

Default scan

```sh
whatweb <target_ip>
```

Dismiss errors

```sh
whatweb --no-errors 10.10.10.0/24
```

Set aggression level to 3 (*Scale: `1`-`4`, Default: `1`*)

```sh
whatweb -a 3 <target_ip>
```

___
<!-- }}} -->
