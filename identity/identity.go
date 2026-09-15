// Package identity owns a workload's SVID (its SPIFFE X.509 identity document)
// and the trust bundle it verifies peers against.
//
// One rule shapes this package: nothing else in the library caches a
// certificate. Every other package asks a Source at the moment of use. SVIDs are
// short lived by design (SPIRE defaults to one hour), so a cached copy anywhere
// else would turn routine rotation into a stale-credential bug.
package identity

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
)

// Source is the read side of a workload identity. The transport package depends
// on this interface and never on a concrete certificate, which is what lets the
// same transport code run against an in-process CA during development and
// against a real SPIRE agent in a cluster.
type Source interface {
	// SPIFFEID is this workload's own identity, for example
	// "spiffe://corp.example/ns/prod/sa/orders".
	SPIFFEID() string

	// TLSCertificate is the current SVID, ready to hand to crypto/tls.
	TLSCertificate() (*tls.Certificate, error)

	// Roots is the current trust bundle: the CA certificates that a peer's
	// SVID must chain to.
	Roots() []*x509.Certificate

	// Rotations yields one value each time the SVID is replaced. The client
	// transport listens on this so it can drop idle connections and
	// re-handshake with the new certificate instead of pinning the old one
	// for the life of the connection pool.
	Rotations() <-chan struct{}

	Close() error
}

// Static is a Source over a single in-process key pair. It backs the tests and
// the demo, which have to run on a laptop with no SPIRE agent installed. The
// deployment-time source is NewSPIRESource.
type Static struct {
	mu    sync.RWMutex
	id    string
	chain []*x509.Certificate
	key   crypto.PrivateKey
	roots []*x509.Certificate

	rotations chan struct{}
	closeOnce sync.Once
}

// NewStatic builds a Source from an already-issued SVID. chain is the leaf
// first, followed by any intermediates; roots is the trust bundle.
func NewStatic(chain []*x509.Certificate, key crypto.PrivateKey, roots []*x509.Certificate) (*Static, error) {
	if len(chain) == 0 {
		return nil, errors.New("identity: empty certificate chain")
	}
	id, err := SPIFFEIDOf(chain[0])
	if err != nil {
		return nil, err
	}
	return &Static{
		id:    id,
		chain: chain,
		key:   key,
		roots: roots,
		// Buffered by one: a rotation event carries no payload, so a second
		// event arriving before the first is read says nothing new.
		rotations: make(chan struct{}, 1),
	}, nil
}

func (s *Static) SPIFFEID() string { return s.id }

func (s *Static) TLSCertificate() (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.chain) == 0 || s.key == nil {
		return nil, errors.New("identity: no SVID")
	}
	der := make([][]byte, 0, len(s.chain))
	for _, c := range s.chain {
		der = append(der, c.Raw)
	}
	return &tls.Certificate{Certificate: der, PrivateKey: s.key, Leaf: s.chain[0]}, nil
}

func (s *Static) Roots() []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*x509.Certificate(nil), s.roots...)
}

func (s *Static) Rotations() <-chan struct{} { return s.rotations }

// Rotate swaps in a freshly issued SVID for the same identity and publishes a
// rotation event. It is how the tests exercise rotation without waiting out an
// SVID lifetime.
//
// The identity must not change. A rotation that returns a different SPIFFE ID
// is not a rotation, it is a different workload, and silently accepting one
// would let a re-issued certificate quietly change who this process claims to
// be.
func (s *Static) Rotate(chain []*x509.Certificate, key crypto.PrivateKey) error {
	if len(chain) == 0 {
		return errors.New("identity: empty certificate chain")
	}
	id, err := SPIFFEIDOf(chain[0])
	if err != nil {
		return err
	}
	if id != s.id {
		return errors.New("identity: a rotated SVID must keep the same SPIFFE ID")
	}

	s.mu.Lock()
	s.chain, s.key = chain, key
	s.mu.Unlock()

	select {
	case s.rotations <- struct{}{}:
	default: // an unread event already says what this one would say
	}
	return nil
}

func (s *Static) Close() error {
	s.closeOnce.Do(func() { close(s.rotations) })
	return nil
}

// SPIFFEIDOf reads the identity out of an SVID.
//
// A SPIFFE identity lives in the certificate's URI SAN, not in the subject or a
// DNS name. A certificate carrying more than one URI SAN is malformed: there is
// no rule for choosing between them, so it is rejected rather than guessed at.
func SPIFFEIDOf(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("identity: no certificate")
	}
	if len(cert.URIs) != 1 {
		return "", errors.New("identity: an SVID carries exactly one URI SAN")
	}
	id := cert.URIs[0].String()
	if !strings.HasPrefix(id, "spiffe://") {
		return "", errors.New("identity: URI SAN is not a SPIFFE ID")
	}
	return id, nil
}
