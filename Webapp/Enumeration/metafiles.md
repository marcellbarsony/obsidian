# Metafiles

## Humans.txt

`humans.txt` is an initiative for knowing the people behind a website.
It's a TXT file that contains information about the people who have contributed
to building the website.

### Sources

- [Humanstxt.org](https://humanstxt.org/)

### Location

`humans.txt` is located in the web server root, next to `robots.txt`.

```http
https://www.example.com/humans.txt
```

## Robots.txt

**Robots.txt** is used for implementing the **Robots Exclusion Protocol**
([RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html)),
telling the search engine crawlers which URLs they cannot access.

`robots.txt` is located in the web server root

```http
https://example.com/robots.txt
```

## Security.txt

`security.txt` is a standard which allows websites to define security standards.

### Sources

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

### Sources

- [Wikipedia - Sitemaps](https://en.wikipedia.org/wiki/Sitemaps)
