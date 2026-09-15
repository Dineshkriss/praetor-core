# praetor-core: the code and the flow

This document explains what is in this repository, how a request moves through
it, why the code is shaped the way it is, and where it sits in the wider
project.

It covers pillars 1 and 2 of the project only. Pillars 3 and 4 are described at
a high level in [DESIGN-DELEGATION-OPA.md](DESIGN-DELEGATION-OPA.md) and are not
implemented here.

## 1. Where this fits

The project is a sidecar-free service-to-service authentication library for Go
microservices. It has four pillars:

| Pillar | What it does | Status in this repo |
| --- | --- | --- |
| 1. Workload identity | Each service gets a cryptographic identity (a SPIFFE SVID) instead of a shared secret | Implemented |
| 2. In-process mutual TLS | Both ends of every call prove that identity, inside the application process | Implemented |
| 3. Authorization | A policy decides what a proven caller is allowed to do | Design only |
| 4. Delegation token | Carries the end user's identity safely across several hops | Design only |

Pillars 1 and 2 answer "who is calling". Pillars 3 and 4 answer "and may they
do this, on whose behalf". The second pair only makes sense once the first pair
is solid, which is why they are built in this order.

The word "sidecar-free" is the point of pillar 2. In a service mesh, a proxy
container runs next to every service and terminates TLS for it. Here the same Go
process that runs the handler also terminates TLS, so there is no extra
container, no extra network hop, and no gap between what the proxy verified and
what the application believes.

## 2. Layout

```
identity/     what this workload is, and who it trusts
  identity.go   the Source interface, SPIFFE ID parsing, and the in-process source
  spire.go      the SPIRE Workload API source, for deployment

transport/    turning that identity into mutual TLS
  transport.go  server and client TLS config, peer identity, HTTP helpers

internal/devca/  a stand-in CA so tests and the demo run without SPIRE
cmd/demo/        prints the identities of two sample services
```

About 690 lines of Go, plus an 80 line demo and 370 lines of tests. The
dependency list is one entry, `go-spiffe`, and it is used only by `spire.go`.
Everything else is the standard library, which keeps the trust decisions in code
that can be read in an afternoon.

Two names to keep straight while reading the code. **self** is this workload's
own identity, the one we present. **peer** is whoever is at the other end, the
one we verify. Every connection does both, and both sides run the same code, so
the pair appears throughout.

## 3. The central abstraction

Everything hangs off one interface in `identity/identity.go`:

```go
type Source interface {
    SPIFFEID() string
    TLSCertificate() (*tls.Certificate, error)
    TrustBundle() []*x509.Certificate
    Rotations() <-chan struct{}
    Close() error
}
```

Two implementations satisfy it:

- `identity.StaticSource` holds one key pair in memory. The tests and the demo
  use it, because they have to run on a laptop with no SPIRE agent.
- `identity.SPIRESource` streams SVIDs from a local SPIRE agent over the
  Workload API. This is the deployment path.

The transport package depends on the interface and never on either concrete
type. That is what makes the demo honest: the code being demonstrated is
byte-for-byte the code that will run against SPIRE. Only the constructor changes.

There is one rule the whole design rests on: **no package other than `identity`
caches a certificate**. Every caller asks the `Source` at the moment of use. The
reason is rotation. SVIDs are deliberately short lived, an hour by default in
SPIRE, so a certificate copied into a `tls.Config` at startup would be stale
within the hour. By fetching per handshake, rotation costs nothing and needs no
invalidation logic anywhere else.

## 4. Flow A: getting an identity

```
  workload process                     SPIRE agent (deployment)
  ----------------                     ------------------------
  NewSPIRESource(ctx, socket, timeout)
        |
        |  connect over the Unix socket
        +------------------------------------> attest this process
        |                                      (what binary, what pod,
        |                                       what service account)
        |  <----------------------------------- SVID + trust bundle
        |
        |  no SVID inside the timeout?  ->  return an error, do not serve
        |
        +-- goroutine: watch for updates ----> new SVID before expiry
                                               publishes a rotation event
```

Two decisions are worth defending here.

**Startup is fail closed.** If no SVID arrives inside the timeout, the
constructor returns an error and the service never starts serving. A grace
period was considered and rejected: a service that accepts unauthenticated
traffic for thirty seconds after a node restart is exactly the hole this library
exists to close.

**The workload never sees a key file.** It never loads a certificate from disk,
so there is no secret to mount, rotate by hand, or leak in an image layer. The
agent decides what this process is, based on attestation, and hands it an
identity that matches.

In this repository, `internal/devca` plays the role of the signing half of
SPIRE. It issues certificates with a SPIFFE ID in the URI SAN, the same shape a
real SVID has, so the verification code exercised by the tests is the real code.
What it deliberately does not do is attestation: it will sign anything it is
asked to sign. That is why it lives under `internal/` and cannot be imported by
anyone using the library.

## 5. Flow B: one request, end to end

```
  gateway                                                      orders
  -------                                                      ------
  transport.ClientTo(self, ordersID)
        |
        |--- TLS 1.3 ClientHello ----------------------------------->
        |
        |    GetClientCertificate: ask the Source now,
        |    so a rotated SVID is used immediately
        |
        |<-- server SVID + certificate request ---------------------|
        |
        |    VerifyPeerCertificate -> verifyPeer(..., ServerAuth):
        |      1. chain terminates in our trust bundle
        |      2. leaf carries exactly one SPIFFE ID in its URI SAN
        |      3. Authorizer accepts that ID (here: must be ordersID)
        |
        |--- client SVID ------------------------------------------->
        |
        |                       VerifyPeerCertificate -> verifyPeer(..., ClientAuth):
        |                         the same three steps, in the other direction
        |
        |=== handshake complete, both ends proven ==================|
        |
        |--- GET /orders ------------------------------------------->
        |                                        handler calls
        |                                        transport.PeerID(r)
        |                                        -> "spiffe://.../gateway"
        |<-- 200 ---------------------------------------------------|
```

The important property is that a caller without a valid SVID never reaches a
handler. The rejection happens inside the TLS handshake, which is the cheapest
possible place for it, and it means application code cannot forget to check.

Both directions run through the same function, `verifyPeer`. A client and a
server therefore apply identical rules to each other, and there is exactly one
place in the repository where the trust decision is made.

## 6. Design decisions worth explaining

**Server side uses `RequireAnyClientCert`, not `RequireAndVerifyClientCert`.**
That name looks alarming until you see the next line. Go's built-in verification
would check the chain against a `ClientCAs` pool captured when the config was
built. The trust bundle can change while the process runs, so we verify by hand
in `VerifyPeerCertificate` against roots read at handshake time. `RequireAny`
still guarantees a certificate is presented; it just hands us the verification
instead of doing a stale version of it.
`TestCallerWithoutCertificateIsRejected` exercises this setting.

**Client side sets `InsecureSkipVerify: true`.** This is the line that most
needs justification in a review, and it is not a weakening. An SVID carries no
DNS SAN. Its identity is the URI SAN. So the standard hostname check would
always fail, and even if it passed it would be checking the wrong property:
"does the name I dialled match the certificate" rather than "is this the
workload I meant". The flag disables only the built-in hostname and chain check,
and `VerifyPeerCertificate` then runs unconditionally and does more: full chain
validation against the live bundle, plus an exact SPIFFE ID match.
`TestClientRejectsTheWrongServerIdentity` shows the result: the client reaches a
completely valid, fully trusted service and still refuses to send the request,
because it is not the service it asked for.

**Authorization is a one-line seam.** `transport.Authorizer` is
`func(peerID string) error`. Today it is `AllowAnyTrustedPeer` or `AllowOnly`.
This is deliberately the shape that pillar 3 needs: OPA replaces the body of
that function and nothing around it changes.

**Rotation closes idle connections rather than tearing them down.** When the
`Source` publishes a rotation, `RoundTripper` calls `CloseIdleConnections`. The
next request re-handshakes with the new SVID, while requests already in flight
finish on the old connection instead of failing mid-response. Certificates
verified at handshake time stay valid for the life of that connection, which is
standard TLS behaviour and the reason short SVID lifetimes are workable at all.

**`PeerID` returns a boolean, not just a string.** A handler that forgets to
check it gets an empty identity rather than a plausible one. The handlers here
return 401 when it is false. That branch should be unreachable given the TLS
config, and it is there so that a future misconfiguration fails closed instead
of serving anonymous traffic.

## 7. What the demo shows

`go run ./cmd/demo` issues identities for two sample services and prints them.
It makes no network calls. Its only job is to make a workload identity concrete,
because "SVID" on a slide is abstract until you see one.

```
trust domain : corp.example
trust bundle : 1 CA certificate(s), subject "corp.example dev CA"

gateway
  identity   : spiffe://corp.example/ns/prod/sa/gateway   (Source.SPIFFEID)
  URI SAN    : spiffe://corp.example/ns/prod/sa/gateway   (read back off the certificate)
  subject    : ""   (empty: identity does not live here)
  issuer     : corp.example dev CA
  serial     : e8e4e733da520693619bee2077dc6aa0
  key        : ECDSA
  signature  : ECDSA-SHA256
  valid for  : 1h0m0s (until 2026-09-15T08:04:26Z)
  usable as  : [server client]
```

Three things to point at:

- The **identity** and the **URI SAN** are the same string. The first comes from
  `Source.SPIFFEID()`, the second is read straight off the certificate. That is
  the whole of `SPIFFEIDOf`: the identity is not configured anywhere, it is read
  from the credential.
- The **subject** is empty. A conventional TLS certificate puts the name there.
  An SVID does not, which is why hostname verification is the wrong check.
- The lifetime is **one hour**, matching the SPIRE default, and both services
  are usable as client and server, because each is a caller on one connection
  and a callee on the next.

## 8. Tests: where the behaviour is actually proven

The demo shows what an identity looks like. The test suite is what shows the
enforcement works. `go test ./...` covers:

| Test | What it proves |
| --- | --- |
| `TestMutualTLSRoundTrip` | The happy path works and the handler learns the caller's identity from the connection |
| `TestCallerWithoutCertificateIsRejected` | An unauthenticated process on the network cannot reach a handler |
| `TestCallerFromUntrustedCAIsRejected` | A well-formed certificate with a valid SPIFFE ID is useless without the right issuer |
| `TestClientRejectsTheWrongServerIdentity` | Naming the callee stops a trusted but unintended peer receiving the request |
| `TestCallsSurviveAnSVIDRotation` | Rotation does not break in-flight service |
| `TestMalformedCertificatesAreRefused` | Zero, two, or non-SPIFFE URI SANs are all refused rather than guessed at |
| `TestTrustBundleIsCopiedNotShared` | A caller cannot edit our trust anchors |
| `TestRotateRefusesADifferentIdentity` | A rotation cannot quietly change who this process claims to be |

`TestCallerFromUntrustedCAIsRejected` is the one to point at in a review. The
rogue certificate parses cleanly and claims the same SPIFFE ID as a real
service. It fails on one thing only: the chain does not terminate in our trust
bundle.

Every rejection in those tests is a real TLS handshake failure, not a mocked
one. Run `go test -v ./...` to read them off one by one. The suite is race
clean.

## 9. Honest status

- The SPIRE source compiles and is wired to the same interface, but it has not
  yet been run against a live SPIRE server. Standing up SPIRE is scheduled work.
  Everything demonstrated today runs on `identity.StaticSource` and the dev CA.
- `internal/devca` performs no attestation. It is a signing stand-in for tests
  and the demo, nothing more.
- No performance numbers are claimed in this repository. The comparison against
  a sidecar mesh has not been run, so any figure quoted elsewhere is a target
  and not a measurement.
- Pillars 3 and 4 are design only. See the companion document.

## 10. Running it

```
go test ./...        # unit tests
go test -race ./...  # the same, race detector on
go run ./cmd/demo    # the four-call demonstration
```
