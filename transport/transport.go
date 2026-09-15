// Package transport turns a workload identity into mutual TLS, in process.
//
// There is no sidecar and no proxy here: the same Go process that runs the
// application code also terminates TLS, so a peer without a valid SVID is
// rejected inside the TLS handshake and never reaches a handler. That is the
// cheapest possible place to reject it, and it is what removes the per-pod
// proxy from the deployment.
//
// Both directions are verified by the same function, verifyPeer, so a client
// and a server apply identical rules to each other.
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

// Authorizer decides whether a peer that has already proved its SPIFFE ID may
// be talked to. Chain validation has happened by the time this is called, so
// the question here is only "is this the right workload", never "is this
// certificate real".
//
// This is the seam where policy evaluation will be added later. Today it is a
// name comparison; the OPA layer replaces the body of this function without
// changing anything around it.
type Authorizer func(peerID string) error

// AllowAnyInBundle accepts any peer holding a valid SVID from our trust domain.
// It is the right default for a service that serves many callers and makes its
// own decision per request.
func AllowAnyInBundle() Authorizer { return func(string) error { return nil } }

// AllowID accepts exactly one SPIFFE ID. An outbound call uses this so that a
// DNS change or a hijacked service address cannot silently redirect the request
// to a workload that was never the intended recipient.
func AllowID(want string) Authorizer {
	return func(got string) error {
		if got != want {
			return fmt.Errorf("transport: peer identity is %q, want %q", got, want)
		}
		return nil
	}
}

// ServerTLSConfig requires and verifies a client SVID on every connection.
func ServerTLSConfig(src identity.Source, allow Authorizer) (*tls.Config, error) {
	if src == nil {
		return nil, errors.New("transport: no identity source")
	}
	if allow == nil {
		allow = AllowAnyInBundle()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,

		// RequireAnyClientCert, not RequireAndVerifyClientCert: Go's built-in
		// verification would use a pool captured when this config was built.
		// We verify by hand below instead, against the roots read at handshake
		// time, so a trust bundle update is picked up without a restart.
		ClientAuth: tls.RequireAnyClientCert,

		// Fetched per handshake rather than captured once, so a rotated SVID
		// is served immediately. identity is the only cache in the process.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return src.TLSCertificate()
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeer(rawCerts, src.Roots(), x509.ExtKeyUsageClientAuth, allow)
		},
	}, nil
}

// ClientTLSConfig presents this workload's SVID and verifies the server's.
//
// Hostname verification is switched off on purpose. An SVID carries no DNS SAN:
// its identity is the URI SAN, so the standard hostname check would always fail
// and would be checking the wrong property anyway. It is replaced by chain
// validation against the trust bundle plus an explicit SPIFFE ID check, which
// is a stricter test than a matching hostname, not a weaker one.
func ClientTLSConfig(src identity.Source, allow Authorizer) (*tls.Config, error) {
	if src == nil {
		return nil, errors.New("transport: no identity source")
	}
	if allow == nil {
		allow = AllowAnyInBundle()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,

		// Disables only the hostname and chain check that crypto/tls would do
		// for us. VerifyPeerCertificate below is unconditional and does more.
		InsecureSkipVerify: true,

		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return src.TLSCertificate()
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeer(rawCerts, src.Roots(), x509.ExtKeyUsageServerAuth, allow)
		},
	}, nil
}

// verifyPeer is the whole trust decision: the peer's chain must terminate in
// our bundle, the leaf must carry a well-formed SPIFFE ID, and the authorizer
// must accept that ID. Any failure aborts the handshake.
func verifyPeer(rawCerts [][]byte, roots []*x509.Certificate, usage x509.ExtKeyUsage, allow Authorizer) error {
	if len(rawCerts) == 0 {
		return errors.New("transport: peer presented no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, der := range rawCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("transport: peer certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         poolOf(roots),
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	}); err != nil {
		return fmt.Errorf("transport: peer SVID does not chain to the trust bundle: %w", err)
	}

	peerID, err := identity.SPIFFEIDOf(certs[0])
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	return allow(peerID)
}

// PeerID returns the SPIFFE ID of the verified peer that made this request.
//
// It reads the leaf the TLS stack has already accepted, so by the time a
// handler can call this the identity is proven. A false result means the
// request did not arrive over verified mutual TLS and must not be served.
func PeerID(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	id, err := identity.SPIFFEIDOf(r.TLS.PeerCertificates[0])
	if err != nil {
		return "", false
	}
	return id, true
}

// NewServer wraps an http.Handler in a listener that speaks mutual TLS. Serve
// it with ServeTLS(l, "", "") : the certificates come from the identity source,
// not from files on disk.
func NewServer(addr string, h http.Handler, src identity.Source, allow Authorizer) (*http.Server, error) {
	cfg, err := ServerTLSConfig(src, allow)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
}

// RoundTripper is an http.RoundTripper over mutual TLS that reacts to SVID
// rotation by closing idle connections, so the next request re-handshakes with
// the current certificate. Requests already in flight finish on the old
// connection rather than being torn down mid-response.
type RoundTripper struct {
	inner *http.Transport
	done  chan struct{}
	once  sync.Once
}

// NewRoundTripper builds the outbound transport for one identity.
func NewRoundTripper(src identity.Source, allow Authorizer) (*RoundTripper, error) {
	cfg, err := ClientTLSConfig(src, allow)
	if err != nil {
		return nil, err
	}
	rt := &RoundTripper{
		inner: &http.Transport{
			TLSClientConfig:     cfg,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		done: make(chan struct{}),
	}
	go rt.watchRotation(src)
	return rt, nil
}

func (rt *RoundTripper) watchRotation(src identity.Source) {
	rotations := src.Rotations()
	for {
		select {
		case <-rt.done:
			return
		case _, open := <-rotations:
			if !open {
				return // the source was closed
			}
			rt.inner.CloseIdleConnections()
		}
	}
}

func (rt *RoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt.inner.RoundTrip(r)
}

// Close stops watching for rotation and releases pooled connections.
func (rt *RoundTripper) Close() error {
	rt.once.Do(func() {
		close(rt.done)
		rt.inner.CloseIdleConnections()
	})
	return nil
}

// ClientTo returns an http.Client that will only complete a handshake with the
// named SPIFFE ID. Prefer it over Client for service-to-service calls: naming
// the callee is free here and it removes a whole class of misrouting.
func ClientTo(src identity.Source, serverID string) (*http.Client, error) {
	return clientWith(src, AllowID(serverID))
}

// Client returns an http.Client that accepts any peer in the trust bundle.
func Client(src identity.Source) (*http.Client, error) {
	return clientWith(src, AllowAnyInBundle())
}

func clientWith(src identity.Source, allow Authorizer) (*http.Client, error) {
	rt, err := NewRoundTripper(src, allow)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: rt, Timeout: 30 * time.Second}, nil
}

func poolOf(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}
