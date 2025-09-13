---
id: Metafiles
aliases: []
tags:
  - Webapp/Enumeration/Metafiles
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Metafiles

## Humans.txt

`humans.txt` is an initiative for knowing the people behind a website.
It's a TXT file that contains information about the people who have contributed
to building the website.

- [Humanstxt.org](https://humanstxt.org/)

### Implementation

`humans.txt` is located in the web server root, next to `robots.txt`.

```http
https://www.example.com/humans.txt
```

## Robots.txt

**Robots.txt** is used for implementing the **Robots Exclusion Protocol**
([RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html)),
telling the search engine crawlers which URLs they cannot access.

- [Robots.txt](https://en.wikipedia.org/wiki/Robots.txt)

### Implementation

`robots.txt` is located in the web server root

```http
https://example.com/robots.txt
```

## Security.txt

`security.txt` is a standard which allows websites to define security standards

- [securitytxt.org](https://securitytxt.org/)
- [Wikipedia - security.txt](https://en.wikipedia.org/wiki/Security.txt)
- [cisa.gov - security.txt: A Simple File with Big Value](https://www.cisa.gov/news-events/news/securitytxt-simple-file-big-value)

### Implementation

`security.txt` is located in the [`/.well-known/`](https://en.wikipedia.org/wiki/Well-known_URI) directory

```http
https://www.google.com/.well-known/security.txt
https://www.facebook.com/.well-known/security.txt
https://github.com/.well-known/security.txt
```

## Sitemap.xml

`sitemap.xml` informs search engines about URLs on a website that are available
for web crawling

- [Wikipedia - Sitemaps](https://en.wikipedia.org/wiki/Sitemaps)

### Output

Prettify the output of `.xml` files by piping them into it

```sh
sitemap.xml | xmllint  --format -
```
