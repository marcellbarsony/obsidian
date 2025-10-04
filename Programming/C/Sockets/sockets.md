# Sockets

```c
#include <sys/types.h>
#include <sys/socket.h>

int socket(int domain, int type, int protocol); 
```

The `socket()` function will return the file descriptor of the socket.

Example:
```c
int s = socket(AF_INET, SOCK_STREAM, 0);
```
