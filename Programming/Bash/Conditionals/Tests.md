---
id: Tests
aliases: []
tags: []
---

# Tests

## Syntax

```sh
[ condition-to-test-for ]
```

> [!example]-
>
>```sh
>[ -e /etc/passwd ]
>```

## File operators

| Operator | Description                                                   |
| -------- | ------------------------------------------------------------- |
| -a FILE  | True if file **exists**                                       |
| -b FILE  | True if file is a **block special**                           |
| -c FILE  | True if file is a **character special**                       |
| -d FILE  | True if file is a **directory**                               |
| -e FILE  | True if file **exists**                                       |
| -f FILE  | True if file **exists** and is a **regular file**             |
| -g FILE  | True if file is **set-group-id**                              |
| -G FILE  | True if file is **effectively owned by your gorup**           |
| -h FILE  | True if file is a **symbolic link**                           |
| -k FILE  | True if file **has its 'sticky' bit set**                     |
| -L FILE  | True if file is a **symbolic link**                           |
| -N FILE  | True if the file **has been modified since it was last read** |
| -O FILE  | True if the file is **effectively owned by you**              |
| -p FILE  | True if file is a **named pipe**                              |
| -r FILE  | True if file is **readable**                                  |
| -s FILE  | True if file **exists** and is **not empty**                  |
| -S FILE  | True if file is a **socket**                                  |
| -t FD    | True if FD **opened on a terminal**                           |
| -u FILE  | True if the file is **set-user-id**                           |
| -w FILE  | True if the file is **writeable**                             |
| -x FILE  | True if file is **executable**                                |

## String operators

| Operator           | Description                       |
| ------------------ | --------------------------------- |
| -z STRING          | True if string is **empty**       |
| -n STRING          | True if string is **not empty**   |
| STRING1 = STRING2  | True if strings are **equal**     |
| STRING1 != STRING2 | True if strings are **not equal** |

## Arithmetic operators

| Operator      | Description                                       |
| ------------- | ------------------------------------------------- |
| arg1 -eq arg2 | True if arg1 is **equal** to arg2                 |
| arg1 -ne arg2 | True if arg1 is **not equal** to arg2             |
| arg1 -lt arg2 | True if arg1 is **less** than arg 2               |
| arg1 -le arg2 | True if arg1 is **less than or equal** to arg2    |
| arg1 -gt arg2 | True if arg1 is **greater** than arg2             |
| arg1 -ge arg2 | True if arg1 is **greater than or equal** to arg2 |
