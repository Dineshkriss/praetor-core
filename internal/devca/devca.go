// Package devca is a stand-in for the part of SPIRE that signs certificates,
// so tests and the demo run on a laptop with nothing installed.
//
// It issues real X.509 certificates with a SPIFFE ID in the URI SAN, the same
// shape a genuine SVID has, which means the verification code being tested is
// the real code.
//
// What it deliberately does not do is attestation: it signs anything it is
// asked to sign. That is why it lives under internal/, where nobody using the
// library can reach it.
package devca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"time"
)

// CA signs SVIDs for one trust domain, the way a SPIRE server would.
type CA struct {
	TrustDomain string
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
}

// SVID is a certificate and its key, as the Workload API would hand them over.
type SVID struct {
	SPIFFEID string
	Chain    []*x509.Certificate
	Key      *ecdsa.PrivateKey
}

// New creates a CA for a trust domain such as "corp.example".
func New(trustDomain string) (*CA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: trustDomain + " dev CA"},
		NotBefore:             now.Add(-time.Minute), // tolerate small clock skew
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{mustURL("spiffe://" + trustDomain)},
	}
	caCert, err := sign(template, template, &caKey.PublicKey, caKey) // self-signed
	if err != nil {
		return nil, err
	}
	return &CA{TrustDomain: trustDomain, caCert: caCert, caKey: caKey}, nil
}

// TrustBundle is what a peer needs in order to verify SVIDs from this CA.
func (ca *CA) TrustBundle() []*x509.Certificate { return []*x509.Certificate{ca.caCert} }

// Issue mints an SVID for a path such as "/ns/prod/sa/orders".
//
// One hour matches the SPIRE default. Short lifetimes are the point: they are
// what make rotation a routine event instead of an incident.
func (ca *CA) Issue(path string) (*SVID, error) { return ca.IssueFor(path, time.Hour) }

// IssueFor mints an SVID with an explicit lifetime. The rotation test needs it
// to produce two different certificates for one identity.
func (ca *CA) IssueFor(path string, lifetime time.Duration) (*SVID, error) {
	workloadKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	spiffeID := "spiffe://" + ca.TrustDomain + path
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{}, // empty on purpose: identity lives in the URI SAN
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Both usages, because every workload is a client on one connection
		// and a server on the next.
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{mustURL(spiffeID)},
	}
	leafCert, err := sign(template, ca.caCert, &workloadKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, err
	}
	return &SVID{
		SPIFFEID: spiffeID,
		Chain:    []*x509.Certificate{leafCert},
		Key:      workloadKey,
	}, nil
}

// sign creates a certificate from template, signed by issuer.
func sign(template, issuer *x509.Certificate, subjectKey *ecdsa.PublicKey, issuerKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, subjectKey, issuerKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func randomSerial() *big.Int {
	maxSerial := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		panic(err) // a broken system RNG is not something to carry on through
	}
	return serial
}

func mustURL(raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return parsed
}
