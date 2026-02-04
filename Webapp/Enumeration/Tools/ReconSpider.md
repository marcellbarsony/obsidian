---
id: ReconSpider
aliases: []
tags:
  - Webapp/Enumeration/Tools/ReconSpider
links: "[[Webapp/Enumeration/General|General]]"
---

# ReconSpider

[ReconSpider](https://github.com/bhavsec/reconspider)
is an OSINT Framework for web crawling

___

<!-- Installation {{{-->
## Installation

Install ReconSpider

<!-- HTB {{{-->
### HTB

Install the [HTB version](https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip)
with preconfigured API keys

1. Install [Scrapy](https://www.scrapy.org/)

Install with [apt](https://en.wikipedia.org/wiki/APT_(software))
(*system-wide*)

```sh
sudo apt install python3-scrapy
```

Install with [pip](https://pypi.org/project/pip/)
(*virtual environment*)

```sh
pip3 install scrapy [--break-system-packages]
```

2. Install [ReconSpider](https://github.com/bhavsec/reconspider)

```sh
wget https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip -O ReconSpider.zip
```
```sh
unzip ReconSpider.zip
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Run ReconSpider

```sh
python3 ReconSpider.py http://$target
```

<!-- Info {{{-->
> [!info]-
>
> The output is stored in `results.json`
>
<!-- }}} -->

___
<!-- }}} -->
