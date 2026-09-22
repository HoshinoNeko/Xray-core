# v26.9.9 + TLS certificate snapshot patch

Base: official tag `v26.9.9`, commit
`52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`.
This fork is a patched build, not an unmodified official release.

Ordinary server TLS certificate hot reload previously replaced an element of a
shared slice while GetCertificate read it. OCSP updates also modified an already
published tls.Certificate. A handshake can retain that pointer after the callback
returns, so locking only the selection function is insufficient.

Each configured server certificate now has an atomic pointer to an immutable
certificate snapshot. Reload workers own cloned configuration; successful PEM
reloads and OCSP changes publish replacement certificates. Published OCSP bytes
are never mutated. Missing, malformed or temporarily mismatched renewal files
preserve the accepted certificate and are retried at the next existing interval.
OCSP failure preserves a previous staple for the same certificate; a newly loaded
certificate never inherits the previous certificate's staple.

SNI selection, rejection of unknown SNI, OCSP refresh intervals and OneTimeLoading
are retained. BuildCertificates returns a static snapshot; callers needing hot
reload use GetTLSConfig. The native Hysteria implementation, wire protocol and
configuration schema are unchanged. The separate dynamically issuing CA path is
not redesigned by this narrowly scoped server-certificate patch.

Verification:

```sh
GOTOOLCHAIN=go1.27.0 go test -race ./transport/internet/tls -run 'TestCertificate|TestExpiredCertificate|TestInsecureCertificates' -count=3 -timeout=90s
```

Tests cover concurrent snapshot reads/OCSP updates, retained certificate pointers,
failed OCSP requests, missing/mismatched renewal files and recovery, source config
immutability, wildcard/unknown SNI, OneTimeLoading, and real TLS handshakes before
and after watcher recovery. XrayR additionally runs its native HY2 TCP/UDP,
disable/re-enable, rollback and accounting lifecycle test with `-race`.

The package also contains unrelated live ECH/DNS tests. Those require reachable
external DNS/HTTPS services and are not part of the isolated certificate suite.
Reload workers are signaled to stop when their shared certificate loader is garbage
collected (including all TLS config clones); cleanup is eventual, not a synchronous
inbound-close hook.
