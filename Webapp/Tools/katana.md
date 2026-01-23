---
id: katana
aliases: []
tags:
  - Webapp/Tools/katana
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

# Katana

[katana](https://github.com/projectdiscovery/katana)
is a next-generation crawling and spidering framework

___

<!-- Install {{{-->
## Install

Install katana and its dependencies

<!-- Info {{{-->
> [!info]
>
> katana requires [Go 1.24+](https://go.dev/doc/install)
>
<!-- }}} -->

1. Install dependencies

```sh
sudo apt install golang
```

2. Add Go bin to [[PATH]]

```sh
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
```

3. Source `.zshrc`

```sh
source ~/.zshrc
```

4. Install [katana](https://github.com/projectdiscovery/katana?tab=readme-ov-file#installation)

```sh
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
```

5. Confirm katana version

```sh
katana -v
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

URL Input

```sh
katana -u https://<target.com>
```

Multiple URL Input

```sh
katana -u https://<target1.com>,https://<target2.com>
```

List input

```sh
katana -list <list.txt>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cat url_list.txt
> ```
>
> ```sh
> https://tesla.com
> https://google.com
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Crawling Mode {{{-->
## Crawling Mode

<!-- Standard {{{-->
### Standard

Standard crawling modality uses the standard go http library
to handle HTTP requests/responses without browser overhead

<!-- }}} -->

<!-- Headless {{{-->
### Headless

Headless mode hooks internal headless calls
to handle HTTP requests/responses
directly within the browser context

<!-- Info {{{-->
> [!info]-
>
> Headless mode advantages
>
> - The HTTP fingerprint (*TLS and user agent*)
>   fully identify the client as a legitimate browser
> - Better coverage since the endpoints are discovered
>   analyzing the standard raw response,
>   as in the previous modality,
>   and also the browser-rendered one with javascript enabled
>
> Headless crawling is optional
> and can be enabled using `-headless` option
>
<!-- }}} -->

Runs headless chrome with `no-sandbox` option
(*useful when running as `root` user*)

```sh
katana -u https://<target.com> -headless -no-sandbox
```

Runs headless Chrome without incognito mode
(*useful when using the local browser*)

```sh
katana -u https://<target.com> -headless -no-incognito
```

Specify additional Chrome options with `-headless-options`

```sh
katana -u https://<target.com> -headless -system-chrome -headless-options --disable-gpu,proxy-server=http://127.0.0.1:8080
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Scope Control {{{-->
## Scope Control

**Field Scope**

Scope crawling to **root domain name** and **all subdomains**
(*e.g., `example.com`*) (*default*)

```sh
katana -u https://<target.com> -fs rdn
```

Scope crawling to given **sub(*domain*)**
(*e.g., `www.example.com` or `api.example.com`*)

```sh
katana -u https://<target.com> -fs fqdn
```

Scope crawling to **domain name keyword**
(*e.g., `example`*)

```sh
katana -u https://<target.com> -fs dn
```

**Crawl Scope**

Scope crawling to directories

```sh
katana -u https://<target.com> -cs login
```

Scope crawling to directories (*list*)

```sh
katana -u https://<target.com> -cs <in_scope.txt>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cat in_scope.txt
> ```
> ```sh
> login/
> admin/
> app/
> wordpress/
> ```
>
<!-- }}} -->

**Crawl Out-Scope**

Exclude directories from the scope

```sh
katana -u https://<target.com> -cos login
```

Exclude directories from the scope (*list*)

```sh
katana -u https://<target.com> -cos <in_scope.txt>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cat in_scope.txt
> ```
> ```sh
> login/
> admin/
> app/
> wordpress/
> ```
>
<!-- }}} -->

**No Scope**

Disable scope and crawl the Internet

> [!danger]

```sh
katana -u https://<target.com> -ns
```

**Display Out-Scope**

Display out-of-scope external URLs

```sh
katana -u https://<target.com> -do
```

___
<!-- }}} -->

<!-- Crawler Configuration {{{-->
## Crawler Configuration

**Depth**

Define the depth to follow the URLs for crawling

```sh
katana -u https://<target.com> -d 5
```

**JavaScript crawling**

<!-- Warning {{{-->
> [!warning]-
>
> Producing false positives if scope is not set
<!-- }}} -->

Enable JavaScript file parsing and crawling

```sh
katana -u https://<target.com> -jc
```

**Known-files**

Enable crawling known files
(*e.g., `robots.txt`, `sitemap.xml`)

```sh
katana -u https://<target.com> -kf robotstxt,sitemapxml
```

___
<!-- }}} -->

<!-- Filter {{{-->
## Filter

> [!warning] Deprecated
>
> Use [[#Output]] template

___
<!-- }}} -->

<!-- Rate Limit {{{-->
## Rate Limit

Configure Rate Limit to avoid getting blocked/banned

**Delay**

Delay in seconds between each new request

```sh
katana -u https://<target.com> -delay 20
```

**Concurrency**

Number of URLs per target to fetch at the same time

```sh
katana -u https://<target.com> -c 20
```

**Paralellism**

Number of targets to process at the same time from list input

```sh
katana -u https://<target.com> -p 20
```

**Rate-Limit**

Maximum number of request to send per second

```sh
katana -u https://<target.com> -rl 100
```

**Rate-Limit Minute**

Maximum number of request to send per minute

```sh
katana -u https://<target.com> -rlm 500
```

## Output
