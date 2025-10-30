---
id: Well-Known
aliases: []
tags:
  - Webapp/Enumeration/Well-Known
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

<!-- Well-Known {{{-->
# Well-Known

The [.well-known standard](https://en.wikipedia.org/wiki/Well-known_URI)
([RFC 8615](https://datatracker.ietf.org/doc/html/rfc8615))
serves as a [standardized directory](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml)
within the website's root

```sh
https://target.com/.well-known/
```

> [!info]-
>
> `/.well-known` centralizes a website's critical metadata

<!-- Security.txt {{{-->
## Security.txt

[/.well-known/security.txt](https://securitytxt.org/) ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html))
is a standard which allows websites to define security standards

> [!info]-
>
> - [Wikipedia - security.txt](https://en.wikipedia.org/wiki/Security.txt)
> - [cisa.gov - security.txt: A Simple File with Big Value](https://www.cisa.gov/news-events/news/securitytxt-simple-file-big-value)

```sh
https://target.com/.well-known/security.txt
```

> [!example]-
>
> ```http
> https://www.google.com/.well-known/security.txt
> ```
> ```sh
> https://www.facebook.com/.well-known/security.txt
> ```
> ```sh
> https://github.com/.well-known/security.txt
> ```

___
<!-- }}} -->

<!-- Change Password {{{-->
## Change Password

[/.well-known/change-password](https://github.com/w3c/webappsec-change-password-url)
provides a standard URL for directing users to a password change page

```sh
https://target.com/.well-known/change-password
```

___
<!-- }}} -->

<!-- OpenID Configuration {{{-->
## OpenID Configuration

[/.well-known/openid-configuration](https://openid.net/specs/openid-connect-discovery-1_0.html)
defines configuration details for [OpenID Connect](https://openid.net/developers/how-connect-works/)


> [!info]-
>
> The `openid-configuration` URI is part of the
> [OpenID Connect Discovery protocol](https://openid.net/specs/openid-connect-discovery-1_0.html),
> an identity layer built on top of the [OAuth 2.0](https://oauth.net/2/)
> protocol.
>
> When a client application wants to use OpenID Connect for authentication,
> it can retrieve the OpenID Connect Provider's configuration.
>
> JSON document containing metadata about
> - the provider's endpoints
> - supported authentication methods
> - token issuance
> - etc.


```sh
https://target.com/.well-known/openid-configuration
```

> [!example]-
>
> ```sh
> https://example.com/.well-known/openid-configuration
> ```
> ```json
> {
>   "issuer": "https://example.com",
>   "authorization_endpoint": "https://example.com/oauth2/authorize",
>   "token_endpoint": "https://example.com/oauth2/token",
>   "userinfo_endpoint": "https://example.com/oauth2/userinfo",
>   "jwks_uri": "https://example.com/oauth2/jwks",
>   "response_types_supported": ["code", "token", "id_token"],
>   "subject_types_supported": ["public"],
>   "id_token_signing_alg_values_supported": ["RS256"],
>   "scopes_supported": ["openid", "profile", "email"]
> }
> ```


___
<!-- }}} -->

<!-- }}} -->
