# Pillars 3 and 4: high-level design

This is a sketch, not a specification. It describes what the authorization and
delegation layers are for, roughly how they work, and how they attach to the
code in this repository. Nothing here is implemented in this repo.

The detailed token format lives in the project's Delegation Token Specification.

## 1. The problem these solve

Mutual TLS proves which *service* is calling. It says nothing about which *user*
the call is for.

Consider a normal request path:

```
  user Alice --> gateway --> orders --> payments
```

With pillars 1 and 2 alone, `payments` can prove it is talking to `orders`. It
cannot tell whether `orders` is acting for Alice, for Bob, or for nobody. So if
`orders` is compromised, it can ask `payments` for anything belonging to anyone,
and every check passes. The attacker uses a trusted service as a deputy. This is
the confused deputy problem, and in a microservice estate it is the gap that
mutual TLS on its own leaves open.

The usual fixes are both unattractive:

- **Forward the user's token in a header.** A compromised service simply edits
  the header. This is the baseline the project measures against, and it fails.
- **Call a central authorization server on every hop.** It works, but it puts a
  network round trip and a single point of failure in the middle of every
  internal call.

Pillar 4 is the project's research contribution: get the same guarantee with no
central server and no sidecar.

## 2. Pillar 3: embedded authorization (OPA)

```
  request arrives over verified mTLS
        |
        v
  +-----------------------------+
  |  peer identity (pillar 2)   |   who is calling
  |  user context (pillar 4)    |   on whose behalf
  |  method, path, resource     |   what they want
  +-----------------------------+
        |
        v
  OPA evaluating a Rego policy, in this process
        |
        +--> allow  -> handler runs
        +--> deny   -> 403, request never reaches the handler
```

The policy engine is Open Policy Agent, compiled into the binary and evaluating
Rego in memory. No policy server is contacted at request time.

Why embedded rather than remote: an in-process evaluation is a function call, so
it does not add a network hop to every request, and it cannot fail separately
from the service it protects. The cost is that policy distribution becomes a
separate concern, since each instance holds its own copy.

Where it attaches to this repository: `transport.Authorizer` is already the
shape this needs.

```go
type Authorizer func(peerID string) error
```

Today that is `AllowID` doing a name comparison. Pillar 3 replaces the body with
a policy evaluation. Nothing around it changes, which is the reason the seam was
put there now rather than later.

## 3. Pillar 4: the delegation token

A compact JWS, ES256 only, minted per hop and carried alongside the mutual TLS
connection. Roughly, it says:

> I am `orders`. I received this request from `gateway`. It is for user Alice.
> I am passing it to `payments`, and it expires in seconds, not hours.

The parts that matter:

| Part | Purpose |
| --- | --- |
| Subject | the end user the request is for |
| Actor | the service currently making the call |
| Audience | the single service allowed to accept this token |
| Binding | ties the token to the mTLS credential it arrives on |
| Origin assertion | the user identity as the gateway signed it, carried unchanged |
| Chain | one signature per hop, so the full path is visible |
| Expiry and nonce | short life, single use |

### The origin assertion

This is the key idea. The gateway signs the user identity **once**, at the edge,
when the user actually authenticated. That signed assertion is copied unchanged
through every hop. Each service adds its own signature around it but cannot
alter what is inside.

So a compromised `orders` can mint a perfectly valid token for the next hop. It
just cannot make that token say "Bob" when the gateway signed "Alice", because
it does not hold the gateway's key. Swapping the subject is exactly the attack
that forwarded headers permit, and the origin assertion is what closes it.

### Three legs replacing the central server

A central authorization server gives you one trusted party that sees the whole
request. Removing it means recovering the same guarantees from three local
checks instead:

1. **Credential binding.** The token only works on the mTLS connection it was
   minted for, so a stolen token is not replayable elsewhere.
2. **Per-hop signature chain.** Every service that touched the request signed
   for it, so the path cannot be forged or shortened after the fact.
3. **A policy rule on who may delegate.** Being able to sign is not the same as
   being allowed to. The Rego policy from pillar 3 decides which services are
   permitted to delegate to which others.

Each leg is checkable locally, by the receiving service, with no network call.

### Verification: seven checks

On arrival, a token passes or fails seven checks, run in order. The first failure
wins and the request is rejected.

| Check | Question | Failure code |
| --- | --- | --- |
| A1 | Did this arrive over verified mutual TLS with a peer identity? | `no_peer_identity` |
| A2 | Does the signing certificate chain to the bundle and match that peer? | `signer_not_peer` |
| A3 | Does the signature verify? | `bad_signature` |
| A4 | Is the actor in the token the peer that actually connected? | `actor_mismatch` |
| A5 | Is this token for us, and still inside its lifetime? | `audience_or_expiry` |
| A6 | Have we seen this token before? | `replay` |
| A7 | Are the subject and binding the ones the origin signed? | `origin_mismatch` |

A1 to A6 are what a careful token implementation would do anyway. A7 is the
contribution: it is the check that a compromised intermediate service cannot
pass while lying about the user.

## 4. Putting it together

```
   Alice
     |  logs in, proves who she is
     v
  +---------+   mTLS + token(sub=Alice, act=gateway, aud=orders)
  | gateway |  ---------------------------------------------------+
  +---------+   signs the ORIGIN ASSERTION here, once              |
                                                                   v
                                                            +---------+
                                    A1..A7, then OPA        | orders  |
                                                            +---------+
                                                                   |
     mTLS + token(sub=Alice, act=orders, aud=payments,             |
                  origin assertion copied unchanged)               |
                                                                   v
                                                            +----------+
                                    A1..A7, then OPA        | payments |
                                                            +----------+

   If orders is compromised and tries sub=Bob:  A7 fails, 401 origin_mismatch
   If orders forges a fresh chain from scratch: OPA denies, 403
```

## 5. Status and next steps

- Pillars 1 and 2: implemented in this repository.
- Pillar 3: designed, and the attachment point (`transport.Authorizer`) exists.
- Pillar 4: designed. The origin assertion needs to be written into the token
  specification, which is currently at v0.5 and predates it.
- The interface change needed to support pillar 4 is additive: signing a token
  requires the SVID private key, which means one extra method on
  `identity.Source`. Nothing in the transport layer has to change.
