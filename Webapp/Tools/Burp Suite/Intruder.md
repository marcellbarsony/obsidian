---
id: Intruder
aliases: []
tags:
  - Webapp/Tools/Burp-Suite/Intruder
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

# Intruder


[Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder)
is a tool for automating customized attacks against web applications
and configure attacks that send the same HTTP request over and over again,
inserting different payloads into predefined positions each time

> [!warning]
>
> The free Burp Community version is throttled
> at a speed of 1 request per second

___

1. Send request to Intruder

```sh
CTRL + I
```

```sh
CONTEXT > Send to Intruder
```

> [!example]-
>
> ![[intruder.png]]

2. Open the Intruder tab

```
CTRL + SHIFT + I
```

> [!example]-
>
> ![[intruder-tab.png]]

<!-- Positions {{{-->
## Positions

**Positions** marks the payload position pointer

1. Highlight a position

2. Click `Add §`

> [!example]-
>
> ![[intruder-positions.png]]

___
<!-- }}} -->

<!-- Payloads {{{-->
## Payloads

Configure

- Payload Position & Payload Type
- Payload Configuration
- Payload Processing
- Payload Encoding

> [!example]-
>
> ![[intruder-payloads.png]]

___
<!-- }}} -->
