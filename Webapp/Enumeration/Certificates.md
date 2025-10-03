---
id: Certificates
aliases: []
tags:
  - Webapp/Enumeration/Certificates
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Certificates

- [Crt.sh](https://crt.sh)

## SSL Certificates

### Subdomains

[Inspect](https://crt.sh) the SSL certificates, as [Certificate Transparency](https://en.wikipedia.org/wiki/Certificate_Transparency)
logs may expose subdomains.

#### Certificate Transparency

**Certificate Transparency** is a process ([RFC-6962](https://datatracker.ietf.org/doc/html/rfc6962))
intended to enable the verification of issued digital certificates for encrypted
Internet connections. This is intended to enable the detection of false or
maliciously issued certificates for a domain. SSL certificate providers like
Let's Encrypt share this with the web interface [crt.sh](https://crt.sh), which
stores the new entries in its database.

##### List Certificates

List SSL certificates

```sh
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
```

> [!info]-
>
> - `-s`: Silent mode, suppress progress bars and error messages

##### List Subdomains

Filter SSL certificate by unique subdomains

```sh
curl -s https://crt.sh/\?q\=<example.com>\&output\=json | \
  jq . | \
  grep name | \
  cut -d":" -f2 | \
  grep -v "CN=" | \
  cut -d'"' -f2 | \
  awk '{gsub(/\\n/,"\n");}1;' | \
  sort -ucurl -s https://crt.sh/\?q\=<example.com>\&output\=json | \
  jq . | \
  grep name | \
  cut -d":" -f2 | \
  grep -v "CN=" | \
  cut -d'"' -f2 | \
  awk '{gsub(/\\n/,"\n");}1;' | \
  sort -u
```

> [!example]-
>
>```sh
>curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | \
>  jq . | \
>  grep name | \
>  cut -d":" -f2 | \
>  grep -v "CN=" | \
>  cut -d'"' -f2 | \
>  awk '{gsub(/\\n/,"\n");}1;' | \
>  sort -ucurl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | \
>  jq . | \
>  grep name | \
>  cut -d":" -f2 | \
>  grep -v "CN=" | \
>  cut -d'"' -f2 | \
>  awk '{gsub(/\\n/,"\n");}1;' | \
>  sort -u
>```
