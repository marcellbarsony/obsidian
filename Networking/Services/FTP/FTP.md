---
id: FTP
aliases: []
tags: []
links: "[[Services]]"
---

# File Transfer Protocol (FTP)

**FTP** is a standard plain-text protocol for file transfer across a computer
network, between a server and a client.
```sh
PORT   STATE SERVICE
21/tcp open  ftp
```

**Active FTP** - The FTP client initiates the control connection from its port
*N* to the FTP server's command port (21). The client then listens to port *N+1*
and sends the port *N+1* to the FTP server.

**Passive FTP** - The FTP client initiates the control connection from its port
*N* to port 21 of the FTP server. After this, the client issues a *passv*
command. The server then sends one of its port number *M* to the client.
Finally, the client initiate the data connection from its port *P* to port *M*
of the server.
