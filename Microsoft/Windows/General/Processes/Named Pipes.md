---
id: Named Pipes
aliases: []
tags:
  - Microsoft/Windows/Processes/Named-Pipes
links: "[[Windows]]"
---


# Named Pipes

[Named Pipes](https://en.wikipedia.org/wiki/Named_pipe) (*a.k.a FIFO*)
on Windows are files stored in memory that get cleared out after being read
and is one of the methods of inter-process communication
(*[IPC](https://en.wikipedia.org/wiki/Inter-process_communication)*)

> [!example]
>
> ```sh
> \\.\PipeName\\ExampleNamedPipeServer
> ```

___

<!-- Pipe Communication {{{-->
## Pipe Communication

Windows systems use a Client-Server implementation

- **SERVER**: The process that creates a named pipe
- **CLIENT**: The process communicating with the named pipe

Named pipes can communicate using

- **half-duplex** (*one-way*) channel
  with the client only being able to write data to the server
- **duplex** (*two-way*) channel
  that allows the client to write data over the pipe,
  and the server to respond back with data

Every active connection to a named pipe server
results in the creation of a new named pipe

___
<!-- }}} -->
