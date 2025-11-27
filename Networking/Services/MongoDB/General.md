---
id: General
aliases: []
tags:
  - Networking/Services/MongoDB/General
ports:
    - 27017
    - 27018
---

# General

MongoDB is a popular open-source NoSQL database
that uses a document-oriented data model.
Unlike traditional relational databases, MongoDB stores data in flexible,
JSON-like documents called BSON (Binary JSON).
This makes it highly scalable and perfect for handling large volumes
of unstructured or semi-structured data.
MongoDB is widely used in modern web applications, big data,
real-time analytics, and content management systems.

___

## Configuration

### Dangerous Settings

<!-- Dangerous Settings {{{-->
> [!danger]- Dangerous Settings
>
> Security Misconfigurations
>
> - No authentication enabled
> - Default credentials
> - Exposed to internet without firewall
> - Bind to `0.0.0.0` instead of localhost
> - JavaScript execution enabled
> - No SSL/TLS encryption
> - Weak passwords
> - Excessive user privileges
> - No role-based access control
> - Logging disabled
> - Outdated MongoDB version
> - No regular backups
> - Default port (`27017`) exposed
<!-- }}} -->
