---
id: POST Method
aliases: []
tags:
  - Webapp/General/Methods/POST
---

# POST Method

[POST request method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/POST)
sends data to the server typically using [HTML forms](https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Forms)

The encoding may be one of the following

- `application/x-www-form-urlencoded`: The keys and values
  are encoded in key-value tuples separated by an ampersand (`&`)
  with an equals symbol (`=`) between the key and the value
  (*e.g., `first-name=Frida&last-name=Kahlo`*)
- `multipart/form-data`: Each value is sent as a block of data ("body part"),
  with a user agent-defined delimiter separating each part
  (*e.g., `boundary="delimiter12345`"*).
  The keys are described in the [[Content-Disposition]] header
  of each part or block of data.
- `text/plain`

___
