# Scapy

## Create packet

```py
packet = IP(ttl=10)
```

| Abbreviation  | Description               |
| ------------- | ------------------------- |
| ttl           | Time To Live              |
| src           | Source IP                 |
| dst           | Destination IP            |

## Stack layers

The `/` operator has been used as a composition operator between two layers.

```py
Ether()/IP()/TCP()/UDP()
```

## Send packet

- `send()` - send packets at layer 3.
- `sendp()` - send packets at layer 2.
- `sr()` - send packets and receive answers.
- `sr1()` - return the answer packet.
- `srp()` - return layer 2 packet.

Return sent packet list by passing `return_packets=True`.

## Read PCAP files

```py
a=rdpcap("/path/to/file.pcap")
```

| Command                   | Effect                                               |
| ------------------------- | ---------------------------------------------------- |
| raw(pkt)                  | Assemble the packet                                  |
| hexdump(pkt)              | Hexadecimal dump                                     |
| ls(pkt)                   | List of field values                                 |
| pkt.summary()             | One-line packet summary                              |
| pkt.show()                | Advanced packet summary                              |
| pkt.show2()               | Advanced packet summary on the assembled packet      |
| pkt.sprintf()             | Fill a format string with field values               |
| pkt.decode_payload_as()   | Decode payload decode                                |
| pkt.psdump()              | Draw PostScript diagram                              |
| pkt.pdfdump()             | Draw a PDF                                           |
| pkt.command()             | Return a Scapy command that can generate the packet  |

## Injecting bytes

```py
pkt = IP(len=RawVal(b"NotAnInteger"), src="127.0.0.1")
```

## Sniffing

| Arguments                 | Effect                                                                    |
| ------------------------- | ------------------------------------------------------------------------- |
| filter                    | Filter packets using [BPF syntax](https://www.biot.com/capstats/bpf.html) |
| iface                     | Define interface                                                          |
| prn                       | Callback function for each captured packet                                |
| store                     | Store packets (T/F)                                                       |

## Examples

Access packet's layer
```py
packet[scapy.layer_to_access]
```
