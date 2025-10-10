---
id: General
aliases:
  - Virtual Network Computing
tags:
  - Networking/Services/VNC/General
links: "[[Services]]"
port:
  - 5800
  - 5801
  - 5900
  - 5901
---

# VNC

**VNC** ([Virtual Network Computing](https://en.wikipedia.org/wiki/VNC))
is a graphical desktop-sharing system that utilizes the
**RFB** ([Remote Frame Buffer](https://en.wikipedia.org/wiki/RFB_(protocol)))
protocol to remotely control another computer.

**VNC** transmits the keyboard and mouse events bidirectionally, allowing
real-time access.

## Connect

Connect with [Real VNC](https://www.realvnc.com/en/connect/download/viewer/)

```sh
vncviewer [-passwd passwd.txt] <IP>::5901
```
