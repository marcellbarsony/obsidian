---
id: Crawling
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Crawling
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Crawling

[Web Crawling](https://en.wikipedia.org/wiki/Web_crawler)
(*or web spidering*) is an automated technique
used to systematically browse the web and extract important data
(*e.g., links, metadata, sensitive files, comments, etc.*)

<!-- Methodology {{{-->
## Methodology

### Breadth-First

**Breadth-First Crawling** prioritizes exploring a website's width
before its depth.

**Breadth-First Crawling** starts crawling all the links on the seed page,
then moves on to the links on those pages.

### Depth-First

**Depth-First Crawling** prioritizes exploring a website's depth
before its width.

**Depth-First Crawling** follows a single path of links as far as possible
before backtracking nd exploring other paths.

___
<!-- }}} -->

<!-- ReconSpider {{{-->
## ReconSpider

OSINT Framework for web crawling

1. Install [Scrapy](https://www.scrapy.org/)

<!-- Example {{{-->
> [!example]-
>
> Install with [apt](https://en.wikipedia.org/wiki/APT_(software))
> (*system-wide*)
>
> ```sh
> sudo apt install python3-scrapy
> ```
>
> Install with [pip](https://pypi.org/project/pip/)
> (*virtual environment*)
>
> ```sh
> pip3 install scrapy
> ```
<!-- }}} -->

2. Install [ReconSpider](https://github.com/bhavsec/reconspider)

<!-- Example {{{-->
> [!example]-
>
> > [!info]
> >
> > Install with preconfigured API keys
>
> ```sh
> wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
> ```
> ```sh
> unzip ReconSpider.zip 
> ```
<!-- }}} -->

3. Run ReconSpider

<!-- Example {{{-->
> [!example]-
>
> ```sh
> python3 ReconSpider.py http://<target>
> ```
<!-- }}} -->

The output is stored in `results.json`

___
<!-- }}} -->
