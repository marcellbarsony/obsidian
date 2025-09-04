# Proxy

A proxy is when a device or service sits in the middle of a connection and acts
as a *mediator*.

## Forward Proxy

A **forward proxy** (dedicated proxy) acts as an intermediary server between
clients on a private network and resources on the internet, typically used to
filter requests, cache data, or enforce security policies. It intercepts the
client's requests, completes them on behalf of the client, and then returns the
server's response to the client.

**Forward proxies** are often used in corporate networks to monitor and control
internet traffic, ensuring that clients access only permitted content and protecting
users from malicious sites by masking the client's true IP address.

### Bypass

**Forward proxies** can be bypassed by by using techniques such as tunneling,
where they encapsulate traffic in a different protocol (e.g., HTTP over HTTPS,
SSH) to avoid detection.

- [HackTricks - Proxy/WAF Protection bypass](https://book.hacktricks.wiki/en/pentesting-web/proxy-waf-protections-bypass.html)

## Reverse Proxy

A **reverse proxy** acts as an intermediary server between clients on the
internet and resources on a private network, typically used to enhance security
by concealing the identity of the of the backend servers.


### Bypass

Penetration Testers usually configuring reverse proxies on infected endpoints.
The infected endpoint will listen on a port and send any client that connects to
the port back to the attacker through the infected endpoint. This is useful to
bypass firewalls or evade logging.

- [HackTricks - Proxy/WAF Protection bypass](https://book.hacktricks.wiki/en/pentesting-web/proxy-waf-protections-bypass.html)

## Forward Proxy vs Reverse Proxy

![proxy](./pics/proxy-01.png)

## (Non-) Transparent Proxy

Proxies may be configured to operate in either transparent or non-transparent
mode.

With a **transparent proxy**, the client doesn't know about its existence.
The transparent proxy intercepts the client's communication requests to the
Internet and acts as a substitute instance. To the outside, the transparent
proxy, like the non-transparent proxy, acts as a communication partner.

In the case of a **non-transparent proxy**, a client must know about its
existence. The software the we want to use should be configured to use the proxy
server.

