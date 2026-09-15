// Package identity answers two questions for a workload:
// "who am I" (my SVID) and "who do I trust" (my trust bundle).
//
// An SVID is an X.509 certificate whose URI SAN holds a SPIFFE ID such as
// spiffe://corp.example/ns/prod/sa/orders. That URI is the identity. Not the
// hostname, not the subject.
//
// Design rule for the whole library: only this package holds a certificate.
// Everyone else asks at the moment of use. SVIDs expire in about an hour, so a
// copy stashed anywhere else goes stale and nobody notices.
package identity

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
)

// Source is a live workload identity. The transport package talks to this
// interface only, never to a concrete type, which is why the exact same
// transport code runs against a dev CA in tests and against SPIRE in a cluster.
type Source interface {
	// SPIFFEID is this workload's own identity.
	SPIFFEID() string

	// TLSCertificate is the current SVID, ready for crypto/tls.
	TLSCertificate() (*tls.Certificate, error)

	// TrustBundle is the set of CAs a peer's SVID must chain to.
	TrustBundle() []*x509.Certificate

	// Rotations fires once per SVID replacement. The client transport uses it
	// to drop idle connections so the next call uses the new certificate.
	Rotations() <-chan struct{}

	Close() error
}

// StaticSource is an identity held in memory, issued up front. Tests and the
// demo use it because they run on a laptop with no SPIRE agent.
// SPIRESource is the deployment equivalent.
type StaticSource struct {
	mu          sync.RWMutex
	spiffeID    string
	svidChain   []*x509.Certificate // leaf first, then any intermediates
	privateKey  crypto.PrivateKey
	trustBundle []*x509.Certificate

	rotations chan struct{}
	closeOnce sync.Once
}

// NewStaticSource wraps an already-issued SVID as a Source.
func NewStaticSource(svidChain []*x509.Certificate, privateKey crypto.PrivateKey, trustBundle []*x509.Certificate) (*StaticSource, error) {
	if len(svidChain) == 0 {
		return nil, errors.New("identity: empty SVID chain")
	}
	spiffeID, err := SPIFFEIDOf(svidChain[0])
	if err != nil {
		return nil, err
	}
	return &StaticSource{
		spiffeID:    spiffeID,
		svidChain:   svidChain,
		privateKey:  privateKey,
		trustBundle: trustBundle,
		// Size 1: the event carries no data, so a second unread event would
		// say nothing the first does not.
		rotations: make(chan struct{}, 1),
	}, nil
}

func (s *StaticSource) SPIFFEID() string { return s.spiffeID }

func (s *StaticSource) TLSCertificate() (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.svidChain) == 0 || s.privateKey == nil {
		return nil, errors.New("identity: no SVID")
	}
	rawChain := make([][]byte, 0, len(s.svidChain))
	for _, cert := range s.svidChain {
		rawChain = append(rawChain, cert.Raw)
	}
	return &tls.Certificate{
		Certificate: rawChain,
		PrivateKey:  s.privateKey,
		Leaf:        s.svidChain[0],
	}, nil
}

// TrustBundle returns a copy, so a caller cannot edit our trust anchors.
func (s *StaticSource) TrustBundle() []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*x509.Certificate(nil), s.trustBundle...)
}

func (s *StaticSource) Rotations() <-chan struct{} { return s.rotations }

// Rotate swaps in a freshly issued SVID and announces it. Real rotation is
// SPIRE's job; this exists so tests can trigger one without waiting an hour.
//
// The SPIFFE ID must not change. A new certificate under a different identity
// is not a rotation, it is a different workload, and accepting it would let
// this process quietly start impersonating someone else.
func (s *StaticSource) Rotate(svidChain []*x509.Certificate, privateKey crypto.PrivateKey) error {
	if len(svidChain) == 0 {
		return errors.New("identity: empty SVID chain")
	}
	spiffeID, err := SPIFFEIDOf(svidChain[0])
	if err != nil {
		return err
	}
	if spiffeID != s.spiffeID {
		return errors.New("identity: a rotated SVID must keep the same SPIFFE ID")
	}

	s.mu.Lock()
	s.svidChain, s.privateKey = svidChain, privateKey
	s.mu.Unlock()

	select {
	case s.rotations <- struct{}{}:
	default: // an unread event is already pending
	}
	return nil
}

func (s *StaticSource) Close() error {
	s.closeOnce.Do(func() { close(s.rotations) })
	return nil
}

// SPIFFEIDOf pulls the identity out of an SVID.
//
// Exactly one URI SAN is required. Zero means the certificate names no
// workload; two or more means it names several and there is no rule for
// picking. Both are rejected rather than guessed at, because guessing here
// would mean guessing who the caller is.
func SPIFFEIDOf(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("identity: no certificate")
	}
	if len(cert.URIs) != 1 {
		return "", errors.New("identity: an SVID carries exactly one URI SAN")
	}
	spiffeID := cert.URIs[0].String()
	if !strings.HasPrefix(spiffeID, "spiffe://") {
		return "", errors.New("identity: URI SAN is not a SPIFFE ID")
	}
	return spiffeID, nil
}
