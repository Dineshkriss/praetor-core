// Package devca issues SPIFFE-compatible X.509 SVIDs in process, so the
// library can be tested and demonstrated on a laptop with no SPIRE deployment.
//
// It stands in for the part of SPIRE that signs certificates, and for nothing
// else: there is no attestation here, so it must never be used outside tests
// and demos. It is internal/ precisely so that it cannot be imported by a
// consumer of this library.
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

// CA signs SVIDs for a single trust domain, the way one SPIRE server would.
type CA struct {
	TrustDomain string
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
}

// SVID is a leaf certificate and its private key, as the Workload API would
// hand them to a workload.
type SVID struct {
	SPIFFEID string
	Chain    []*x509.Certificate
	Key      *ecdsa.PrivateKey
}

// New creates a CA for a trust domain such as "corp.example".
func New(trustDomain string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: trustDomain + " dev CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{mustURL("spiffe://" + trustDomain)},
	}
	cert, err := selfSign(tmpl, key)
	if err != nil {
		return nil, err
	}
	return &CA{TrustDomain: trustDomain, cert: cert, key: key}, nil
}

// Roots is the trust bundle for this CA.
func (c *CA) Roots() []*x509.Certificate { return []*x509.Certificate{c.cert} }

// Issue mints an SVID for a path such as "/ns/prod/sa/orders". The one hour
// lifetime matches the SPIRE default and is short on purpose: it is what makes
// rotation a normal event rather than an incident.
func (c *CA) Issue(path string) (*SVID, error) { return c.IssueFor(path, time.Hour) }

// IssueFor mints an SVID with an explicit lifetime, which the rotation test
// needs in order to produce two distinct certificates for one identity.
func (c *CA) IssueFor(path string, ttl time.Duration) (*SVID, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := "spiffe://" + c.TrustDomain + path
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{}, // an SVID carries identity in the URI SAN, not here
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Both usages: every workload is a client on one connection and a
		// server on the next.
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{mustURL(id)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &SVID{SPIFFEID: id, Chain: []*x509.Certificate{cert}, Key: key}, nil
}

func selfSign(tmpl *x509.Certificate, key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err) // a failing system RNG is not something to carry on through
	}
	return n
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
