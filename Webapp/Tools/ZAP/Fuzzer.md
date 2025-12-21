---
id: Fuzzer
aliases: []
tags:
  - Webapp/Tools/ZAP/Fuzzer
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

# ZAP Fuzzer

[Fuzzing](https://www.zaproxy.org/docs/desktop/addons/fuzzer/)
is a technique of submitting lots of data to a target
(*often in the form of invalid or unexpected inputs*)

___

<!-- Fuzzer {{{-->
## Fuzzer

Open the [Fuzzer dialog](https://www.zaproxy.org/docs/desktop/addons/fuzzer/dialogue/)

```sh
Context > Attack > Fuzz
```

<!-- Example {{{-->
> [!example]-
>
> ![[fuzzer-context.png]]
<!-- }}} -->

<!-- Locations {{{-->
### Locations

[Fuzz Location Processors dialog](https://www.zaproxy.org/docs/desktop/addons/fuzzer/locations/)
allows to select the payload processors
to use with all payload generators

1. Select location to fuzz

<!-- Example {{{-->
> [!example]-
>
> ![[fuzzer-dialog.png]]
<!-- }}} -->

2. Click on `Add...` to add a fuzz location

<!-- Example {{{-->
> [!example]-
>
> ![[fuzzer-locations.png]]
<!-- }}} -->

3. Click on `Add...` to add a fuzzer payload

<!-- Example {{{-->
> [!example]-
>
> ![[fuzzer-add-payload.png]]
<!-- }}} -->

4. Configure [[#Processors]] (*optional*)

5. Click `Start Fuzzer`

<!-- Example {{{-->
> [!example]-
>
> ![[fuzzer-start.png]]
<!-- }}} -->

<!-- }}} -->

<!-- Processors {{{-->
### Processors

[Payload Processors dialog](https://www.zaproxy.org/docs/desktop/addons/fuzzer/processors/)
allows to select the payload processors to use with specific payload generators

<!-- Payload Processors {{{-->
> [!info]- Payload Processors
>
> Built-in Payload Processors
>
> - Base64 Decode
> - Base64 Encode
> - Expand (to a minimum specified length)
> - JavaScript Escape
> - JavaScript Unescape
> - MD5 Hash
> - Postfix String
> - Prefix String
> - SHA-1 Hash
> - SHA-256 Hash
> - SHA-512 Hash
> - Trim
> - URL Decode
> - URL Encode
<!-- }}} -->

1. Open the `Fuzz Location Processors` dialog

<!-- Example {{{-->
> [!example]-
>
>![[fuzzer-processors.png]]
<!-- }}} -->

2. Click `Add...` to open `Add Processor`

3. Select a payload processor

<!-- Example {{{-->
> [!example]-
>
>![[fuzzer-processor-add.png]]
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
