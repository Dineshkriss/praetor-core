# praetor-core

Workload identity and in-process mutual TLS for Go microservices, with no
sidecar and no certificate files on disk.

This is the foundation layer of the praetor project (20CYS495). It covers two
of the four pillars:

- **Workload identity.** Each service holds a short-lived SPIFFE SVID, obtained
  from a SPIRE agent at runtime rather than mounted as a secret.
- **In-process mutual TLS.** Both ends of every call prove that identity inside
  the application process, so a caller without a valid SVID is rejected during
  the TLS handshake and never reaches a handler.

Authorization and user delegation are the other two pillars. They are sketched
in [docs/DESIGN-DELEGATION-OPA.md](docs/DESIGN-DELEGATION-OPA.md) and are not
implemented here.

## Try it

```
go run ./cmd/demo   # issue identities for two services and print them
go test -v ./...    # prove the enforcement works
```

The demo makes a workload identity concrete: two sample services, their SPIFFE
IDs, and the certificates behind them. Note that the identity read from the
`Source` and the URI SAN read off the certificate are the same string, and that
the subject is empty, which is why hostname verification is the wrong check for
an SVID.

The tests are where the behaviour is proven: a caller with no certificate, a
caller signed by an untrusted CA, and a caller that reached the wrong service
are each refused, and calls keep working across an SVID rotation. Every
rejection is a real TLS handshake failure, not a mock.

## Using it

```go
// Deployment: identity comes from the local SPIRE agent.
self, err := identity.NewSPIRESource(ctx, "unix:///run/spire/sockets/agent.sock", 30*time.Second)
defer self.Close()

// Serve. Callers must present a valid SVID from the trust bundle.
srv, err := transport.NewServer(":8443", handler, self, transport.AllowAnyTrustedPeer())
srv.ServeTLS(listener, "", "")   // no cert files: they come from self

// Inside a handler, the caller's identity is already proven.
peer, ok := transport.PeerID(r)

// Call out, refusing to talk to anything but the intended service.
client, err := transport.ClientTo(self, "spiffe://corp.example/ns/prod/sa/orders")
```

## Documentation

- [docs/CODE-AND-FLOW.md](docs/CODE-AND-FLOW.md): what the code does, how a
  request flows through it, why it is built this way, and where it fits in the
  project.
- [docs/DESIGN-DELEGATION-OPA.md](docs/DESIGN-DELEGATION-OPA.md): high-level
  design for the authorization and delegation layers.

## Status

Implemented and tested: the identity source interface, the in-process source,
the SPIRE Workload API source, mutual TLS in both directions, peer identity
extraction, and SVID rotation.

Not yet done: the SPIRE source has not been run against a live SPIRE server, so
the tests and demo use an in-process dev CA. No performance comparison against a
sidecar mesh has been run, so this repository claims no performance numbers.
