---
id: Crawling
aliases: []
tags:
  - Webapp/Enumeration/Discovery/Crawling
links: "[[Webapp/Enumeration/General|General]]"
---

# Crawling

[Web Crawling](https://en.wikipedia.org/wiki/Web_crawler)
(*or web spidering*) is an automated technique
used to systematically browse the web and extract important data
(*e.g., links, metadata, sensitive files, comments, etc.*)

<!-- Info {{{-->
> [!info]- Web Crawlers
>
> - [[Burp Suite]]'s Spider
> - [[ReconSpider]]
> - [OWASP ZAP](https://www.zaproxy.org/) (*Zed Attack Proxy*)
> - [Scrapy](https://www.scrapy.org/) (*Python framework*)
> - [Apache Nutch](https://nutch.apache.org/) (*Scalable Crawler*)
> - [[Katana]]
>
<!-- }}} -->

___

<!-- General {{{-->
## General

<!-- Methodology {{{-->
### Methodology

**Breadth-First Search** (*[BFS](https://en.wikipedia.org/wiki/Breadth-first_search)*)
and **Depth-First Search** (*[DFS](https://en.wikipedia.org/wiki/Depth-first_search)*)
are two fundamental algorithms used for traversing or searching
graphs and trees:

- **Breadth-First Crawling** starts crawling all the links on the seed page,
  then moves on to the links on those pages

- **Depth-First Crawling** follows a single path of links as far as possible
  before backtracking nd exploring other paths

<!-- Info {{{-->
> [!info]-
>
> **Breadth-First Crawling** prioritizes exploring a website's width
> before its depth
>
> **Depth-First Crawling** prioritizes exploring a website's depth
> before its width
>
> ![[crawling-methodology.png]]
>
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Crawling {{{-->
## Crawling

[[Katana]]

```sh
katana -u https://<target.com>
```

[[ReconSpider]]

```sh
python3 ReconSpider.py http://<target.com>
```

<!-- Info {{{-->
> [!info]-
>
> The output is stored in `results.json`
>
<!-- }}} -->

___
<!-- }}} -->
