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
    grep <target> | \
    cut -d" " -f1,4; \
done
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> for i in $(cat subdomainlist); do \
>     host $i | \
>     grep "has address" | \
>     grep inlanefreight.com | \
>     cut -d" " -f1,4; \
> done
> ```
> ```sh
> blog.inlanefreight.com 10.129.24.93
> inlanefreight.com 10.129.27.33
> matomo.inlanefreight.com 10.129.127.22
> www.inlanefreight.com 10.129.127.33
> s3-website-us-west-2.amazonaws.com 10.129.95.250
> ```
<!-- }}} -->
___

<!-- Google Dorks {{{-->
## Google Dorks

Google search combined with Google Dorks can expose cloud resources

```
inurl:amazonaws.com
inurl:blob.core.windows.net
```
___
<!-- }}} -->

<!-- Cloud Storages {{{-->
## Cloud Storages

Discover
[AWS](https://en.wikipedia.org/wiki/Amazon_Web_Services),
[Azure](https://en.wikipedia.org/wiki/Microsoft_Azure), and
[GCP](https://en.wikipedia.org/wiki/Google_Cloud_Platform)
cloud storages

- [GrayHatWarfare](https://buckets.grayhatwarfare.com/)

___
<!-- }}} -->

<!-- Leaked SSH Keys {{{-->
## Leaked SSH Keys

Expose leaked private or public SSH keys

- [GrayHatWarfare](https://grayhatwarfare.com/)
- [GrayHatWarfare - Buckets](https://buckets.grayhatwarfare.com/)
  (*`Search Files`*)

___
<!-- }}} -->

<!-- Website Source Code {{{-->
## Website Source Code

The company website's source code may expose cloud resources

```html
<link rel="dns-prefetch" href="//<company>.blob.core.windows.net"/>
<link rel="preconnect" href="//<company>.blob.core.windows.net" crossorigin/>
```
___
<!-- }}} -->
