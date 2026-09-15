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

// SPIRESource streams SVIDs from the local SPIRE agent. Not yet run against a
// live SPIRE server.
type SPIRESource struct {
	spire *workloadapi.X509Source

	rotations chan struct{}
	stop      chan struct{}
	closeOnce sync.Once
}

// NewSPIRESource connects to the agent socket, for example
// unix:///run/spire/sockets/agent.sock. It fails if no SVID arrives in time,
// so a workload without an identity never starts serving.
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

// watchForRotations turns go-spiffe update signals into our own events, so no
// other package has to import go-spiffe.
func (s *SPIRESource) watchForRotations() {
	updated := s.spire.Updated()
	for {
		select {
		case <-s.stop:
			return
		case <-updated:
			updated = s.spire.Updated()
			select {
			case s.rotations <- struct{}{}:
			default:
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
