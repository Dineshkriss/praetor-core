package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIRESource is the deployment identity: SVIDs streamed from the SPIRE agent
// running on the same node, refreshed by the agent before they expire.
//
// The workload never reads a key from disk. There is no secret to mount, no
// certificate to renew by hand, and nothing to leak in an image layer. The
// agent decides what this process is by attesting it, then hands over a
// matching SVID.
//
// Status for the review: this compiles and satisfies the same Source interface,
// but it has not been run against a live SPIRE server yet. Today's demo and
// tests use StaticSource.
type SPIRESource struct {
	spire *workloadapi.X509Source

	rotations chan struct{}
	stop      chan struct{}
	closeOnce sync.Once
}

// NewSPIRESource connects to the agent's Unix socket, for example
// unix:///run/spire/sockets/agent.sock.
//
// Fail closed: no SVID inside startupTimeout means an error, and the caller
// never starts serving. A grace period was considered and rejected. A service
// that accepts unauthenticated traffic for thirty seconds after a node restart
// is the exact hole this library exists to close.
func NewSPIRESource(ctx context.Context, socketPath string, startupTimeout time.Duration) (*SPIRESource, error) {
	if socketPath == "" {
		return nil, errors.New("identity: no Workload API socket path")
	}
	if startupTimeout <= 0 {
		startupTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()

	spire, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, fmt.Errorf("identity: workload API at %s: %w", socketPath, err)
	}
	// Connecting is not enough. Prove an SVID actually arrived.
	if _, err := spire.GetX509SVID(); err != nil {
		spire.Close()
		return nil, fmt.Errorf("identity: no SVID from the workload API: %w", err)
	}

	source := &SPIRESource{
		spire:     spire,
		rotations: make(chan struct{}, 1),
		stop:      make(chan struct{}),
	}
	go source.watchForRotations()
	return source, nil
}

// watchForRotations translates go-spiffe's update signal into our own event, so
// that no other package in the library has to import go-spiffe.
func (s *SPIRESource) watchForRotations() {
	updated := s.spire.Updated()
	for {
		select {
		case <-s.stop:
			return
		case <-updated:
			updated = s.spire.Updated() // single-use channel, re-arm it
			select {
			case s.rotations <- struct{}{}:
			default: // an unread event is already pending
			}
		}
	}
}

func (s *SPIRESource) SPIFFEID() string {
	svid, err := s.spire.GetX509SVID()
	if err != nil {
		return ""
	}
	return svid.ID.String()
}

func (s *SPIRESource) TLSCertificate() (*tls.Certificate, error) {
	svid, err := s.spire.GetX509SVID()
	if err != nil {
		return nil, err
	}
	rawChain := make([][]byte, 0, len(svid.Certificates))
	for _, cert := range svid.Certificates {
		rawChain = append(rawChain, cert.Raw)
	}
	return &tls.Certificate{
		Certificate: rawChain,
		PrivateKey:  svid.PrivateKey,
		Leaf:        svid.Certificates[0],
	}, nil
}

func (s *SPIRESource) TrustBundle() []*x509.Certificate {
	svid, err := s.spire.GetX509SVID()
	if err != nil {
		return nil
	}
	bundle, err := s.spire.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return nil
	}
	return bundle.X509Authorities()
}

func (s *SPIRESource) Rotations() <-chan struct{} { return s.rotations }

func (s *SPIRESource) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.stop)
		err = s.spire.Close()
	})
	return err
}
