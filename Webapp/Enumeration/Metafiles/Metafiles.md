---
id: Metafiles
aliases: []
tags:
  - Webapp/Enumeration/Metafiles
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Metafiles

___

<!-- Humans.txt {{{-->
## Humans.txt

[humans.txt](https://humanstxt.org/) is an initiative for knowing the people
behind a website. It's a TXT file that contains information about the people who
have contributed to building the website

`humans.txt` is located in the web server root, next to `robots.txt`

```sh
https://target.com/humans.txt
```

<!-- Example {{{-->
> [!example]-
>
> ```http
> https://www.example.com/humans.txt
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Robots.txt {{{-->
## Robots.txt

[robots.txt](https://en.wikipedia.org/wiki/Robots.txt) is used for implementing
the **Robots Exclusion Protocol** ([RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html)),
telling the search engine crawlers which URLs they cannot access

`robots.txt` is located in the web server root

```sh
https://target.com/robots.txt
```

<!-- Example {{{-->
> [!example]-
>
> ```http
> https://example.com/robots.txt
> ```
>
> ```sh
> User-agent: *
> Disallow: /admin/
> Disallow: /private/
> Allow: /public/
>
> User-agent: Googlebot
> Crawl-delay: 10
>
> Sitemap: https://www.example.com/sitemap.xml
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Sitemap.xml {{{-->
## Sitemap.xml

[Sitemaps](https://en.wikipedia.org/wiki/Sitemaps)
informs search engines about URLs on a website
that are available for web crawling

```sh
https://target.com/sitemap.xml
```

Prettify the output of `.xml` files by piping them into it

```sh
sitemap.xml | xmllint  --format -
```
___
<!-- }}} -->
