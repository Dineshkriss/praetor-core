// Package transport builds mutual TLS from a workload identity, in process.
// "self" is our own identity, "peer" is whoever is on the other end.
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

// Authorizer decides whether an authenticated peer is one we want to talk to.
// Policy evaluation will replace the body of these later.
type Authorizer func(peerID string) error

// AllowAnyTrustedPeer accepts any workload with a valid SVID from our bundle.
func AllowAnyTrustedPeer() Authorizer { return func(string) error { return nil } }

// AllowOnly accepts one named SPIFFE ID and nothing else.
func AllowOnly(expectedID string) Authorizer {
	return func(actualID string) error {
		if actualID != expectedID {
			return fmt.Errorf("transport: peer identity is %q, want %q", actualID, expectedID)
		}
		return nil
	}
}

// ServerTLSConfig requires a valid SVID from every caller.
func ServerTLSConfig(self identity.Source, authorize Authorizer) (*tls.Config, error) {
	if self == nil {
		return nil, errors.New("transport: no identity source")
	}
	if authorize == nil {
		authorize = AllowAnyTrustedPeer()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,

		// Not RequireAndVerify: that checks against a ClientCAs pool frozen at
		// config time. verifyPeer below uses the bundle as it is now.
		ClientAuth: tls.RequireAnyClientCert,

		// Fetched per handshake so a rotated SVID is served immediately.
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

		// An SVID has no DNS name, so the built-in hostname check cannot apply.
		// verifyPeer below replaces it with a stricter SPIFFE ID check.
		InsecureSkipVerify: true,

		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return self.TLSCertificate()
		},
		VerifyPeerCertificate: func(rawPeerChain [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeer(rawPeerChain, self.TrustBundle(), x509.ExtKeyUsageServerAuth, authorize)
		},
	}, nil
}

// verifyPeer is the trust decision, used by both sides of a connection.
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

	// Does the chain end at a CA we trust?
	if _, err := peerLeaf.Verify(x509.VerifyOptions{
		Roots:         asCertPool(trustBundle),
		Intermediates: asCertPool(intermediates),
		KeyUsages:     []x509.ExtKeyUsage{requiredUsage},
	}); err != nil {
		return fmt.Errorf("transport: peer SVID does not chain to the trust bundle: %w", err)
	}

	// Who is it, and do we want to talk to them?
	peerID, err := identity.SPIFFEIDOf(peerLeaf)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	return authorize(peerID)
}

// PeerID returns the SPIFFE ID of the caller. False means the request did not
// arrive over verified mutual TLS.
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

// NewServer wraps a handler in mutual TLS. Serve it with ServeTLS(l, "", ""):
// the certificate comes from the identity source, not from disk.
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
// rotation.
type RoundTripper struct {
	inner *http.Transport
	done  chan struct{}
	once  sync.Once
}

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

// watchForRotations drops idle connections on rotation, so the next request
// re-handshakes with the new SVID while in-flight ones finish on the old.
func (rt *RoundTripper) watchForRotations(self identity.Source) {
	rotations := self.Rotations()
	for {
		select {
		case <-rt.done:
			return
		case _, stillOpen := <-rotations:
			if !stillOpen {
				return
			}
			rt.inner.CloseIdleConnections()
		}
	}
}

func (rt *RoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt.inner.RoundTrip(r)
}

func (rt *RoundTripper) Close() error {
	rt.once.Do(func() {
		close(rt.done)
		rt.inner.CloseIdleConnections()
	})
	return nil
}

// ClientTo returns a client that will only talk to the named service.
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
