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
go test ./...       # unit tests
go run ./cmd/demo   # one service, four calls: one allowed, three blocked
```

The demo brings up a service and shows a valid caller getting through, then a
caller with no certificate, a caller signed by an untrusted CA, and a caller
that reached the wrong service all being refused. Every rejection is a real TLS
failure, and the demo exits non-zero if any call does the opposite of what it
claims.

## Using it

```go
// Deployment: identity comes from the local SPIRE agent.
src, err := identity.NewSPIRESource(ctx, "unix:///run/spire/sockets/agent.sock", 30*time.Second)
defer src.Close()

// Serve. Callers must present a valid SVID from the trust bundle.
srv, err := transport.NewServer(":8443", handler, src, transport.AllowAnyInBundle())
srv.ServeTLS(ln, "", "")   // no cert files: they come from src

// Inside a handler, the caller's identity is already proven.
peer, ok := transport.PeerID(r)

// Call out, refusing to talk to anything but the intended service.
client, err := transport.ClientTo(src, "spiffe://corp.example/ns/prod/sa/orders")
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
