---
id: WhatWaf
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Tools/WhatWaf
links: "[[Webapp/Enumeration/General|General]]"
---

# WhatWaf

[WhatWaf](https://github.com/Ekultek/WhatWaf) —
Detect and bypass web application firewalls and protection systems

___

<!-- Installation {{{-->
## Installation

[Install](https://github.com/Ekultek/WhatWaf/blob/master/.github/README2.md#installation)
WhatWaf into `~/.whatwaf/.install/bin`

```sh
./setup.sh install
```

Install WhatWaf manually

```sh
sudo -s << EOF
git clone https://github.com/ekultek/whatwaf.git
cd whatwaf
chmod +x whatwaf.py
pip install -r requirements.txt
./whatwaf.py --help
EOF
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Identify WAF

```sh
whatwaf -u <target>
```
___
<!-- }}} -->
