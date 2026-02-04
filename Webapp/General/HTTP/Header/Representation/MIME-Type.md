---
id: General
aliases: []
tags:
  - Webapp/General/HTTP/Header/Representation/MIME-Type
---

# MIME-Type

A [MIME-Type](https://developer.mozilla.org/en-US/docs/Glossary/MIME_type)
(*Multipurpose Internet Mail Extensionsor,
or "media type" and sometimes "content type"*)
is an internet standard that determines the type of a file
through its general format and bytes structure

```sh
MIME-Type: image/png
```

Determining the file's format is usually done
by inspecting the first few bytes of the file's content,
which contains the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures)
or [Magic Bytes](https://web.archive.org/web/20240522030920/https://opensource.apple.com/source/file/file-23/file/magic/magic.mime)

<!-- Example {{{-->
> [!example]-
>
> - GIF: `GIF8`, `GIF87a`, `GIF89a`
> - Text: Plain text
>
<!-- }}} -->
