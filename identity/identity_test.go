package identity_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"

	"github.com/praetor-auth/praetor-core/identity"
	"github.com/praetor-auth/praetor-core/internal/devca"
)

func TestSPIFFEIDOfReadsTheURISAN(t *testing.T) {
	_, svid := issue(t, "corp.example", "/ns/prod/sa/orders")

	got, err := identity.SPIFFEIDOf(svid.Chain[0])
	if err != nil {
		t.Fatalf("SPIFFEIDOf: %v", err)
	}
	if want := "spiffe://corp.example/ns/prod/sa/orders"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A certificate with no SPIFFE ID, two SPIFFE IDs, or a non-SPIFFE URI is
// ambiguous about who the peer is. All three are rejected rather than resolved
// by a guess.
func TestSPIFFEIDOfRejectsMalformedCertificates(t *testing.T) {
	cases := map[string][]*url.URL{
		"no URI SAN":      nil,
		"two URI SANs":    {mustURL(t, "spiffe://corp.example/a"), mustURL(t, "spiffe://corp.example/b")},
		"not a SPIFFE ID": {mustURL(t, "https://corp.example/a")},
	}
	for name, uris := range cases {
		t.Run(name, func(t *testing.T) {
			cert := &x509.Certificate{Subject: pkix.Name{CommonName: "x"}, URIs: uris}
			if _, err := identity.SPIFFEIDOf(cert); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func TestStaticServesTheCurrentSVID(t *testing.T) {
	ca, svid := issue(t, "corp.example", "/ns/prod/sa/orders")
	src, err := identity.NewStatic(svid.Chain, svid.Key, ca.Roots())
	if err != nil {
		t.Fatalf("NewStatic: %v", err)
	}
	defer src.Close()

	if got := src.SPIFFEID(); got != svid.SPIFFEID {
		t.Errorf("SPIFFEID = %q, want %q", got, svid.SPIFFEID)
	}
	cert, err := src.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	if cert.Leaf != svid.Chain[0] {
		t.Error("TLSCertificate returned a different leaf than the one supplied")
	}
}

// Callers must not be able to edit the trust bundle out from under the source.
func TestStaticRootsAreCopied(t *testing.T) {
	ca, svid := issue(t, "corp.example", "/ns/prod/sa/orders")
	src, err := identity.NewStatic(svid.Chain, svid.Key, ca.Roots())
	if err != nil {
		t.Fatalf("NewStatic: %v", err)
	}
	defer src.Close()

	roots := src.Roots()
	roots[0] = nil
	if src.Roots()[0] == nil {
		t.Fatal("mutating the returned slice changed the source's trust bundle")
	}
}

func TestStaticRotatePublishesAnEvent(t *testing.T) {
	ca, svid := issue(t, "corp.example", "/ns/prod/sa/orders")
	src, err := identity.NewStatic(svid.Chain, svid.Key, ca.Roots())
	if err != nil {
		t.Fatalf("NewStatic: %v", err)
	}
	defer src.Close()

	next, err := ca.Issue("/ns/prod/sa/orders")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := src.Rotate(next.Chain, next.Key); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	select {
	case <-src.Rotations():
	default:
		t.Fatal("no rotation event was published")
	}
	cert, err := src.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	if cert.Leaf != next.Chain[0] {
		t.Error("the source is still serving the old SVID")
	}
}

// A re-issued certificate for a different identity is not a rotation. Accepting
// one would let this process quietly start claiming to be another workload.
func TestStaticRotateRejectsADifferentIdentity(t *testing.T) {
	ca, svid := issue(t, "corp.example", "/ns/prod/sa/orders")
	src, err := identity.NewStatic(svid.Chain, svid.Key, ca.Roots())
	if err != nil {
		t.Fatalf("NewStatic: %v", err)
	}
	defer src.Close()

	other, err := ca.Issue("/ns/prod/sa/payments")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := src.Rotate(other.Chain, other.Key); err == nil {
		t.Fatal("expected Rotate to reject a different SPIFFE ID")
	}
}

func issue(t *testing.T, trustDomain, path string) (*devca.CA, *devca.SVID) {
	t.Helper()
	ca, err := devca.New(trustDomain)
	if err != nil {
		t.Fatalf("devca.New: %v", err)
	}
	svid, err := ca.Issue(path)
	if err != nil {
		t.Fatalf("devca issue %s: %v", path, err)
	}
	return ca, svid
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return u
}
