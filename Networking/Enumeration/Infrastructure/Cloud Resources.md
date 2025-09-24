---
id: Cloud Resources
aliases: []
tags:
  - Networking/Enumeration/Infrasturcture/Cloud-Resources
---

# Cloud Resources

Cloud storage may be addede to the DNS list for administrative purposes

```sh
for i in $(cat subdomainlist); do \
    host $i | \
    grep "has address" | \
    grep inlanefreight.com | \
    cut -d" " -f1,4; \
done
```
```sh
blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
www.inlanefreight.com 10.129.127.33
s3-website-us-west-2.amazonaws.com 10.129.95.250
```

## Google Dorks

Google search combined with Google Dorks can expose cloud resources

```
inurl:amazonaws.com
inurl:blob.core.windows.net
```

## Website Source Code

The company website's source code may expose cloud resources

```html
<link rel="dns-prefetch" href="//<company>.blob.core.windows.net"/>
<link rel="preconnect" href="//<company>.blob.core.windows.net" crossorigin/>
```

## Domain.Glass Results

Third-party providers (e.g., [domain.glass](https://domain.glass/)) can also
tell a lot about the company's infrastructure.

## GrayHatWarfare Results

[GrayHatWarfare](https://buckets.grayhatwarfare.com/) can discover AWS, Azure,
and GCP cloud storages.

### Leaked SSH Keys

[GrayHatWarfare](https://buckets.grayhatwarfare.com/) can expose leaked private
or public SSH keys under when searching for the company name under `Search Files`
