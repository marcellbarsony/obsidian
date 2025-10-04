# Bind

`bind` takes the following arguments:
- `sockfd`: socket file descriptor
- `my_addr`: pointer to a `struct sockaddr` that contains information about
  the address
- `addrlen`: the length of the struct

```c
#include <sys/types.h>
#include <sys/socket.h>

int bind(int sockfd, struct sockaddr *my_addr, int addrlen);
```

```c
bind(s, &addr, sizeof(addr))
```
