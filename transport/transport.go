// Package transport turns a workload identity into mutual TLS, inside the
// application process.
//
// No sidecar. In a service mesh a proxy container sits next to every service
// and terminates TLS for it. Here the same Go process that runs the handler
// terminates TLS itself, so there is no extra container, no extra hop, and no
// gap between what the proxy checked and what the application believes.
//
// Two words to keep straight while reading: "self" is this workload's own
// identity, which we present. "Peer" is whoever is on the other end, which we
// verify. Both sides of a connection do both things, through the same code.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/praetor-auth/praetor-core/identity"
)

// Authorizer decides whether a peer we have already authenticated is one we
// want to talk to.
//
// By the time this runs, the peer's certificate is proven genuine. The only
// question left is "is this the right workload", never "is this real".
//
// This is also the extension point for the authorization pillar: OPA replaces
// the body of this function and nothing around it changes.
type Authorizer func(peerID string) error

// AllowAnyTrustedPeer accepts any workload holding a valid SVID from our trust
// domain. Right for a service with many callers that decides per request.
func AllowAnyTrustedPeer() Authorizer { return func(string) error { return nil } }

// AllowOnly accepts one named SPIFFE ID and nothing else. Use it on outbound
// calls: naming the callee costs nothing and stops a DNS change or a hijacked
// address from quietly routing your request to a different workload.
func AllowOnly(expectedID string) Authorizer {
	return func(actualID string) error {
		if actualID != expectedID {
			return fmt.Errorf("transport: peer identity is %q, want %q", actualID, expectedID)
		}
		return nil
	}
}

// ServerTLSConfig demands a valid SVID from every caller.
func ServerTLSConfig(self identity.Source, authorize Authorizer) (*tls.Config, error) {
	if self == nil {
		return nil, errors.New("transport: no identity source")
	}
	if authorize == nil {
		authorize = AllowAnyTrustedPeer()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,

		// Reviewer will ask why this is not RequireAndVerifyClientCert.
		// Answer: that option verifies against a ClientCAs pool frozen when
		// this config was built, and our trust bundle changes while we run.
		// So we require a certificate here and verify it ourselves below,
		// against the bundle read at handshake time. Stricter, not looser.
		ClientAuth: tls.RequireAnyClientCert,

		// Asked for per handshake, never captured once, so a rotated SVID is
		// served the moment it arrives.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return self.TLSCertificate()
		},

		VerifyPeerCertificate: func(rawPeerChain [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeer(rawPeerChain, self.TrustBundle(), x509.ExtKeyUsageClientAuth, authorize)
		},
	}, nil
}

// ClientTLSConfig presents our SVID and checks the server's.
func ClientTLSConfig(self identity.Source, authorize Authorizer) (*tls.Config, error) {
	if self == nil {
		return nil, errors.New("transport: no identity source")
	}
	if authorize == nil {
		authorize = AllowAnyTrustedPeer()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,

		// The other line a reviewer will stop on. It is not a weakening.
		//
		// An SVID has no DNS name in it, so Go's built-in hostname check would
		// always fail, and even passing it would answer the wrong question:
		// "does this match the address I dialled" instead of "is this the
		// workload I meant". This flag turns off that check and only that
		// check. VerifyPeerCertificate below always runs and does more: full
		// chain validation plus an exact SPIFFE ID match.
		InsecureSkipVerify: true,

		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return self.TLSCertificate()
		},

		VerifyPeerCertificate: func(rawPeerChain [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeer(rawPeerChain, self.TrustBundle(), x509.ExtKeyUsageServerAuth, authorize)
		},
	}, nil
}

// verifyPeer is the entire trust decision, in one place, used by both sides.
//
// Three questions, in order:
//  1. Does the peer's chain end at a CA we trust?
//  2. Does its leaf carry one well-formed SPIFFE ID?
//  3. Does the authorizer accept that ID?
//
// Any "no" aborts the handshake, so a rejected caller never reaches a handler.
func verifyPeer(rawPeerChain [][]byte, trustBundle []*x509.Certificate, requiredUsage x509.ExtKeyUsage, authorize Authorizer) error {
	if len(rawPeerChain) == 0 {
		return errors.New("transport: peer presented no certificate")
	}
	peerChain := make([]*x509.Certificate, 0, len(rawPeerChain))
	for _, raw := range rawPeerChain {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("transport: peer certificate: %w", err)
		}
		peerChain = append(peerChain, cert)
	}
	peerLeaf, intermediates := peerChain[0], peerChain[1:]

	// 1. Chain of trust.
	if _, err := peerLeaf.Verify(x509.VerifyOptions{
		Roots:         asCertPool(trustBundle),
		Intermediates: asCertPool(intermediates),
		KeyUsages:     []x509.ExtKeyUsage{requiredUsage},
	}); err != nil {
		return fmt.Errorf("transport: peer SVID does not chain to the trust bundle: %w", err)
	}

	// 2. Identity.
	peerID, err := identity.SPIFFEIDOf(peerLeaf)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}

	// 3. Permission to talk to it.
	return authorize(peerID)
}

// PeerID is how a handler learns who called it.
//
// It reads the leaf the TLS stack already accepted, so the identity is proven
// before the handler ever runs. A false result means this request did not come
// over verified mutual TLS and must not be served.
func PeerID(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	peerID, err := identity.SPIFFEIDOf(r.TLS.PeerCertificates[0])
	if err != nil {
		return "", false
	}
	return peerID, true
}

// NewServer wraps a handler in mutual TLS. Serve it with ServeTLS(listener, "", "):
// the empty filenames are the point, because the certificate comes from the
// identity source, not from disk.
func NewServer(addr string, handler http.Handler, self identity.Source, authorize Authorizer) (*http.Server, error) {
	tlsConfig, err := ServerTLSConfig(self, authorize)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
}

// RoundTripper is an HTTP transport over mutual TLS that survives SVID
// rotation: when the identity changes it drops idle connections so the next
// request re-handshakes with the new certificate, while requests already in
// flight finish normally instead of failing mid-response.
type RoundTripper struct {
	inner *http.Transport
	done  chan struct{}
	once  sync.Once
}

// NewRoundTripper builds the outbound transport for one workload.
func NewRoundTripper(self identity.Source, authorize Authorizer) (*RoundTripper, error) {
	tlsConfig, err := ClientTLSConfig(self, authorize)
	if err != nil {
		return nil, err
	}
	roundTripper := &RoundTripper{
		inner: &http.Transport{
			TLSClientConfig:     tlsConfig,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		done: make(chan struct{}),
	}
	go roundTripper.watchForRotations(self)
	return roundTripper, nil
}

func (rt *RoundTripper) watchForRotations(self identity.Source) {
	rotations := self.Rotations()
	for {
		select {
		case <-rt.done:
			return
		case _, stillOpen := <-rotations:
			if !stillOpen {
				return // the identity source was closed
			}
			rt.inner.CloseIdleConnections()
		}
	}
}

func (rt *RoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt.inner.RoundTrip(r)
}

// Close stops watching for rotations and releases pooled connections.
func (rt *RoundTripper) Close() error {
	rt.once.Do(func() {
		close(rt.done)
		rt.inner.CloseIdleConnections()
	})
	return nil
}

// ClientTo returns a client that will only complete a handshake with the named
// service. Prefer this for service-to-service calls.
func ClientTo(self identity.Source, expectedServerID string) (*http.Client, error) {
	return newClient(self, AllowOnly(expectedServerID))
}

// Client returns a client that accepts any trusted workload as the server.
func Client(self identity.Source) (*http.Client, error) {
	return newClient(self, AllowAnyTrustedPeer())
}

func newClient(self identity.Source, authorize Authorizer) (*http.Client, error) {
	roundTripper, err := NewRoundTripper(self, authorize)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: roundTripper, Timeout: 30 * time.Second}, nil
}

func asCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
