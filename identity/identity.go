// Package identity holds a workload's SVID and its trust bundle.
package identity

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
)

// Source is a workload's live identity.
type Source interface {
	SPIFFEID() string
	TLSCertificate() (*tls.Certificate, error)
	TrustBundle() []*x509.Certificate
	Rotations() <-chan struct{}
	Close() error
}

// StaticSource is an identity held in memory, used by the tests and the demo.
// SPIRESource is the deployment equivalent.
type StaticSource struct {
	mu          sync.RWMutex
	spiffeID    string
	svidChain   []*x509.Certificate
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
		rotations:   make(chan struct{}, 1),
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

// TrustBundle returns a copy, so callers cannot edit our trust anchors.
func (s *StaticSource) TrustBundle() []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*x509.Certificate(nil), s.trustBundle...)
}

func (s *StaticSource) Rotations() <-chan struct{} { return s.rotations }

// Rotate swaps in a new SVID for the same identity and announces it.
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
	default:
	}
	return nil
}

func (s *StaticSource) Close() error {
	s.closeOnce.Do(func() { close(s.rotations) })
	return nil
}

// SPIFFEIDOf reads the SPIFFE ID out of a certificate's URI SAN. Anything other
// than exactly one SPIFFE URI is ambiguous and refused.
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
