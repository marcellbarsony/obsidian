---
id: Crawling
aliases: []
tags:
  - Webapp/Enumeration/Discovery/Crawling
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Crawling

[Web Crawling](https://en.wikipedia.org/wiki/Web_crawler)
(*or web spidering*) is an automated technique
used to systematically browse the web and extract important data
(*e.g., links, metadata, sensitive files, comments, etc.*)

___

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

<!-- Web Crawlers {{{-->
## Web Crawlers

- [[Burp Suite]]'s Spider
- [[ReconSpider]]
- [OWASP ZAP](https://www.zaproxy.org/) (*Zed Attack Proxy*)
- [Scrapy](https://www.scrapy.org/) (*Python framework*)
- [Apache Nutch](https://nutch.apache.org/) (*Scalable Crawler*)

___
<!-- }}} -->
