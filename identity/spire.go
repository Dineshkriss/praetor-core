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

// SPIRESource is the deployment-time identity source. It holds an open stream
// to the local SPIRE agent's Workload API and republishes a rotation event
// whenever the agent pushes a new SVID.
//
// Note on status: this type compiles and is wired into the same Source
// interface as Static, but it has not yet been exercised against a live SPIRE
// server. Standing up SPIRE is scheduled work. Everything demonstrated today
// runs on Static.
type SPIRESource struct {
	source *workloadapi.X509Source

	rotations chan struct{}
	stop      chan struct{}
	closeOnce sync.Once
}

// NewSPIRESource connects to the SPIRE agent listening on socketPath, for
// example "unix:///run/spire/sockets/agent.sock".
//
// Startup is fail closed. If no SVID arrives within startupTimeout the
// constructor returns an error and the caller does not begin serving. A grace
// period was considered and rejected: a service that accepts unauthenticated
// traffic for thirty seconds after a node restart is precisely the gap this
// library exists to close.
func NewSPIRESource(ctx context.Context, socketPath string, startupTimeout time.Duration) (*SPIRESource, error) {
	if socketPath == "" {
		return nil, errors.New("identity: no Workload API socket path")
	}
	if startupTimeout <= 0 {
		startupTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()

	src, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, fmt.Errorf("identity: workload API at %s: %w", socketPath, err)
	}
	if _, err := src.GetX509SVID(); err != nil {
		src.Close()
		return nil, fmt.Errorf("identity: no SVID from the workload API: %w", err)
	}

	s := &SPIRESource{
		source:    src,
		rotations: make(chan struct{}, 1),
		stop:      make(chan struct{}),
	}
	go s.watch()
	return s, nil
}

// watch translates the go-spiffe update signal into our rotation event. The
// two are kept separate so that the rest of the library never imports go-spiffe.
func (s *SPIRESource) watch() {
	updated := s.source.Updated()
	for {
		select {
		case <-s.stop:
			return
		case <-updated:
			updated = s.source.Updated() // the channel is single use, so re-arm
			select {
			case s.rotations <- struct{}{}:
			default:
			}
		}
	}
}

func (s *SPIRESource) SPIFFEID() string {
	svid, err := s.source.GetX509SVID()
	if err != nil {
		return ""
	}
	return svid.ID.String()
}

func (s *SPIRESource) TLSCertificate() (*tls.Certificate, error) {
	svid, err := s.source.GetX509SVID()
	if err != nil {
		return nil, err
	}
	der := make([][]byte, 0, len(svid.Certificates))
	for _, c := range svid.Certificates {
		der = append(der, c.Raw)
	}
	return &tls.Certificate{
		Certificate: der,
		PrivateKey:  svid.PrivateKey,
		Leaf:        svid.Certificates[0],
	}, nil
}

func (s *SPIRESource) Roots() []*x509.Certificate {
	svid, err := s.source.GetX509SVID()
	if err != nil {
		return nil
	}
	bundle, err := s.source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
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
		err = s.source.Close()
	})
	return err
}
