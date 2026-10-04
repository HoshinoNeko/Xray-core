# Hysteria2 UDP datagram integrity on v26.9.9

This fork fixes two inherited v26.9.9 receive-path defects without changing
the wire protocol, authentication, Salamander settings, or QUIC congestion settings.

## Large datagrams

`UDPReader.ReadFrom` previously used the QUIC minimum datagram-frame size (1200)
as its receive-buffer capacity. With path MTU discovery, the actual frames can
be larger. `InterConn.Read` silently copied only the prefix and returned no error.
An observed 4096-byte response was truncated to 3528 bytes: three frames lost
193, 193, and 182 bytes respectively before reassembly.

The receive scratch buffer now accommodates full non-jumbo datagrams. Retained
fragments own their payload bytes, so reuse of scratch storage cannot corrupt
out-of-order reassembly. Undersized `InterConn` and Hysteria reader buffers now
return `io.ErrShortBuffer` instead of silently truncating or dropping data.

The UDP-only internal read buffers, Hysteria serialization storage, `core.Dial`
UDP writes, and `core.DialUDP` writes also preserve packets larger than the regular
8192-byte buffer. TCP buffer sizes and stream behavior remain unchanged. This
requires larger pooled buffers for UDP reads; it is a correctness fix, not a
promise of lower UDP memory usage. Ordinary write buffers are sized on demand.

## Remote-only port hopping

`intervalremote` reuses the original socket, but previously never started its
receive loop: only local socket hopping started a receiver. Remote-only modes
now start one receiver on the original socket and stop it through the existing
Close lifecycle. Server-side forwarding remains the responsibility of XrayR
or the administrator; no server-side `udphop` mask is added.

## Regression coverage

- Fragmentation, reversed fragment arrival, and exact non-repeating payload
  comparison at 11, 1200, 4096, 8192, 16000, and 65507 bytes.
- Explicit short-buffer errors and one-write/one-datagram semantics.
- Native UDP remote-only hopping echo and receiver cleanup.
- XrayR TCP/UDP, traffic reporting, disable/recovery, hot reload, and rollback
  in plain, Salamander, and Salamander + remote-only hopping modes.

Native end-to-end datagram size remains subject to the host's socket limits.
For example, macOS defaults to `net.inet.udp.maxdgram=9216`; the XrayR test probes
the native socket first and reports unsupported large sizes rather than
misclassifying them as protocol failures. Linux deployment should also exercise
16000- and 65507-byte native end-to-end traffic. Protocol-only tests cover both
sizes independently of this operating-system constraint.
