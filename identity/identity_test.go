package identity_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"

	"github.com/praetor-auth/praetor-core/identity"
	"github.com/praetor-auth/praetor-core/internal/devca"
)

func TestSPIFFEIDComesFromTheURISAN(t *testing.T) {
	_, svid := newCAAndSVID(t, "corp.example", "/ns/prod/sa/orders")

	gotID, err := identity.SPIFFEIDOf(svid.Chain[0])
	if err != nil {
		t.Fatalf("SPIFFEIDOf: %v", err)
	}
	if wantID := "spiffe://corp.example/ns/prod/sa/orders"; gotID != wantID {
		t.Errorf("got %q, want %q", gotID, wantID)
	}
}

func TestMalformedCertificatesAreRefused(t *testing.T) {
	malformed := map[string][]*url.URL{
		"no URI SAN":      nil,
		"two URI SANs":    {mustURL(t, "spiffe://corp.example/a"), mustURL(t, "spiffe://corp.example/b")},
		"not a SPIFFE ID": {mustURL(t, "https://corp.example/a")},
	}
	for name, uris := range malformed {
		t.Run(name, func(t *testing.T) {
			cert := &x509.Certificate{Subject: pkix.Name{CommonName: "x"}, URIs: uris}
			if _, err := identity.SPIFFEIDOf(cert); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func TestStaticSourceServesTheCurrentSVID(t *testing.T) {
	ca, svid := newCAAndSVID(t, "corp.example", "/ns/prod/sa/orders")
	source, err := identity.NewStaticSource(svid.Chain, svid.Key, ca.TrustBundle())
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}
	defer source.Close()

	if gotID := source.SPIFFEID(); gotID != svid.SPIFFEID {
		t.Errorf("SPIFFEID = %q, want %q", gotID, svid.SPIFFEID)
	}
	tlsCert, err := source.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	if tlsCert.Leaf != svid.Chain[0] {
		t.Error("TLSCertificate returned a different leaf than the one supplied")
	}
}

func TestTrustBundleIsCopiedNotShared(t *testing.T) {
	ca, svid := newCAAndSVID(t, "corp.example", "/ns/prod/sa/orders")
	source, err := identity.NewStaticSource(svid.Chain, svid.Key, ca.TrustBundle())
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}
	defer source.Close()

	handedBack := source.TrustBundle()
	handedBack[0] = nil

	if source.TrustBundle()[0] == nil {
		t.Fatal("editing the returned slice changed the source's trust bundle")
	}
}

func TestRotateSwapsTheSVIDAndAnnouncesIt(t *testing.T) {
	ca, svid := newCAAndSVID(t, "corp.example", "/ns/prod/sa/orders")
	source, err := identity.NewStaticSource(svid.Chain, svid.Key, ca.TrustBundle())
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}
	defer source.Close()

	renewed, err := ca.Issue("/ns/prod/sa/orders")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := source.Rotate(renewed.Chain, renewed.Key); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	select {
	case <-source.Rotations():
	default:
		t.Fatal("no rotation event was published")
	}

	tlsCert, err := source.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	if tlsCert.Leaf != renewed.Chain[0] {
		t.Error("the source is still serving the old SVID")
	}
}

func TestRotateRefusesADifferentIdentity(t *testing.T) {
	ca, svid := newCAAndSVID(t, "corp.example", "/ns/prod/sa/orders")
	source, err := identity.NewStaticSource(svid.Chain, svid.Key, ca.TrustBundle())
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}
	defer source.Close()

	someoneElse, err := ca.Issue("/ns/prod/sa/payments")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := source.Rotate(someoneElse.Chain, someoneElse.Key); err == nil {
		t.Fatal("expected Rotate to refuse a different SPIFFE ID")
	}
}

func newCAAndSVID(t *testing.T, trustDomain, path string) (*devca.CA, *devca.SVID) {
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

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return parsed
}
