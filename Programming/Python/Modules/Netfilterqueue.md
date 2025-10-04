# NetfilterQueue

<!-- Installation {{{ -->
## Installation

- [GitHub](https://github.com/oremanj/python-netfilterqueue)

[NetfilterQueue](https://pypi.org/project/NetfilterQueue) is a C extension
module that links against libnetfilter_queue. Before installing, ensure you
have:

- A C compiler
- Python development files
- Libnetfilter_queue development files and associated dependencies

```sh
pip install NetfilterQueue
```
<!-- }}} -->

<!-- Usage {{{ -->
## Usage

To send packets to the queue:
```sh
iptables -I <table or chain> <match specification> -j NFQUEUE --queue-num <queue number>

# Example
iptables -I INPUT -d 192.168.0.0/24 -j NFQUEUE --queue-num 1
```

The only special part of the rule is the target. Rules can have any match and
can be added to any table or chain.

Valid queue numbers are integers from 0 to 65,535 inclusive.

To view libnetfilter_queue stats, refer to
`/proc/net/netfilter/nfnetlink_queue`:
```sh
cat /proc/net/netfilter/nfnetlink_queue
1  31621     0 2  4016     0     0        2  1
```

The fields are:
- Queue ID
- Bound process ID
- Number of currently queued packets
- Copy mode
- Copy size
- Number of packets dropped due to reaching max queue size
- Number of packets dropped due to netlink socket failure
- Total number of packets sent to queue
- Something for libnetfilter_queue’s internal use
<!-- }}} -->

<!-- Limitations {{{ -->
## Limitations

We use a fixed-size 4096-byte buffer for packets, so you are likely to see
truncation on loopback and on Ethernet with jumbo packets. If this is a problem,
either lower the MTU on your loopback, disable jumbo packets, or get Python,
change `DEF BufferSize = 4096` in `netfilterqueue.pyx`, and rebuild.

Not all information available from libnetfilter_queue is exposed:
missing pieces include packet input/output network interface names, checksum
offload flags, UID/GID and security context data associated with the packet
(if any).

Not all information available from the kernel is even processed by
libnetfilter_queue: missing pieces include additional link-layer header data
for some packets (including VLAN tags), connection-tracking state, and incoming
packet length (if truncated for queueing).

We do not expose the libnetfilter_queue interface for changing queue flags.
Most of these pertain to other features we don’t support (listed above), but
there’s one that could set the queue to accept (rather than dropping) packets
received when it’s full.
<!-- }}} -->

<!-- NetfilterQueue Objects {{{ -->
## NetfilterQueue Objects

A NetfilterQueue object represents a single queue. Configure your queue
with a call to `bind`, then start receiving packets with a call to `run`.
```sh
NetfilterQueue.bind(queue_num, callback, max_len=1024, mode=COPY_PACKET, range=65535, sock_len=...)
```

Create and bind to the queue:
- `queue_num` uniquely identifies this queue for the kernel.
  It must match the `--queue-num` in your iptables rule, but there is no
  ordering requirement: it’s fine to either `bind()` first or set up the
  iptables rule first.
- `callback` is a function or method that takes one argument, a Packet object
  (see below).
- `max_len` sets the largest number of packets that can be in the queue;
  new packets are dropped if the size of the queue reaches this number.
- `mode` determines how much of the packet data is provided to your script.
  Use the constants above.
- `range` defines how many bytes of the packet you want to get. For example,
  if you only want the source and destination IPs of a IPv4 packet, range
  could be 20.
- `sock_len` sets the receive socket buffer size.

### Remove Queue

Packets matched by your iptables rule will be dropped.
```sh
NetfilterQueue.unbind()
```

### Get file descriptor

Get the file descriptor of the socket used to receive queued packets and send
verdicts. If you’re using an async event loop, you can poll this FD for
readability and call `run(False)` every time data appears on it.
```sh
NetfilterQueue.get_fd()
```

### Send packet to callback

Send packets to your callback. By default, this method blocks, running until
an exception is raised (such as by Ctrl+C). Set `block=False` to process the
pending messages without waiting for more; in conjunction with the `get_fd`
method, you can use this to integrate with async event loops.
```sh
NetfilterQueue.run(block=True)
```

### Send packet to callback (supplied socket)

Send packets to your callback, but use the supplied socket instead of recv,
so that, for example, gevent can monkeypatch it. You can make a socket with
`socket.fromfd(nfqueue.get_fd()`, `socket.AF_NETLINK`, `socket.SOCK_RAW`)
and optionally make it non-blocking with `socket.setblocking(False)`.
```sh
NetfilterQueue.run_socket(socket)
```
<!-- }}} -->

<!-- Packet objects {{{ -->
## Packet objects

Objects of this type are passed to your callback.

### Return packet's payload (byte object)

Return the packet’s payload as a bytes object. The returned value starts with
the IP header. You must call `retain()` if you want to be able to
`get_payload()` after your callback has returned. If you have already called
`set_payload()`, then `get_payload()` returns what you passed to
`set_payload()`.
```sh
Packet.get_payload()
```

### Set packet payload
Set the packet payload. Call this before `accept()` if you want to change the
contents of the packet before allowing it to be released. Don’t forget to
update the transport-layer checksum (or clear it, if you’re using UDP), or
else the recipient is likely to drop the packet. If you’re changing the length
of the packet, you’ll also need to update the IP length, IP header checksum,
and probably some transport-level fields (such as UDP length for UDP).
```sh
Packet.set_payload(payload)
```

### Return payload size

Return the size of the payload.
```sh
Packet.get_payload_len()
```

### Set kernel mark

Give the packet a kernel mark, which can be used in future iptables
rules. `mark` is a 32-bit number.
```sh
Packet.set_mark(mark)
```

### Get packet mark

Get the mark on the packet (either the one you set using `set_mark()`, or the
one it arrived with if you haven’t `called set_mark()`).
```sh
Packet.get_mark()
```

### Get packet hardware address

Return the source hardware address of the packet as a Python bytestring, or
None if the source hardware address was not captured (packets captured by the
`OUTPUT` or `PREROUTING` hooks). For example, on Ethernet the result will be a
six-byte MAC address. The destination hardware address is not available
because it is determined in the kernel only after packet filtering is complete.
```sh
Packet.get_hw()
```

### Get packet timestamp

Return the time at which this packet was received by the kernel, as a floating
point Unix timestamp with microsecond precision (comparable to the result of
`time.time()`, for example). Packets captured by the `OUTPUT` or `POSTROUTING`
hooks do not have a timestamp, and `get_timestamp()` will return 0.0 for them.
```sh
Packet.get_timestamp()
```

### Packet ID

The identifier assigned to this packet by the kernel. Typically the first packet
received by your queue starts at 1 and later ones count up from there.
```sh
Packet.id
```

### Packet link-layer protocol

The link-layer protocol for this packet. For example, IPv4 packets on Ethernet
would have this set to the EtherType for IPv4, which is `0x0800`.
```sh
Packet.hw_protocol
```

### Mark packet

The mark that had been assigned to this packet when it was enqueued.
Unlike the result of `get_mark()`, this does not change if you call
`set_mark()`.
```sh
Packet.mark
```

### Netfilter hook

The netfilter hook (iptables chain, roughly) that diverted this packet into our
queue. Values 0 through 4 correspond to PREROUTING, INPUT, FORWARD, OUTPUT, and
POSTROUTING respectively.
```sh
Packet.hook
```

### Retain packet

Allocate a copy of the packet payload for use after the callback has returned.
`get_payload()` will raise an exception at that point if you didn’t call
`retain()`.
```sh
Packet.retain()
```

### Accept packet

You can reorder packets by accepting them in a different
order than the order in which they were passed to your callback.
```sh
Packet.accept()
```

### Drop packet

Drop the packet.
```sh
Packet.drop()
```

### Repeat packet

Restart processing of this packet from the beginning of its Netfilter hook 
iptables chain, roughly). Any changes made using `set_payload()` or `set_mark()`
are preserved; in the absence of such changes, the packet will probably come
right back to the same queue.
```sh
Packet.repeat()
```
<!-- }}} -->
