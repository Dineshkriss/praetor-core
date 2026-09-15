// Command demo issues identities for two sample services and prints them, so
// you can see what a workload identity actually looks like.
//
//	go run ./cmd/demo
package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"path"
	"time"

	"github.com/praetor-auth/praetor-core/identity"
	"github.com/praetor-auth/praetor-core/internal/devca"
)

func main() {
	// One trust domain. In deployment this CA is SPIRE.
	ca, err := devca.New("corp.example")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("trust domain : %s\n", ca.TrustDomain)
	fmt.Printf("trust bundle : %d CA certificate(s), subject %q\n",
		len(ca.TrustBundle()), ca.TrustBundle()[0].Subject.CommonName)

	// Two services, each issued its own SVID.
	for _, path := range []string{"/ns/prod/sa/gateway", "/ns/prod/sa/orders"} {
		svid, err := ca.Issue(path)
		if err != nil {
			log.Fatal(err)
		}
		source, err := identity.NewStaticSource(svid.Chain, svid.Key, ca.TrustBundle())
		if err != nil {
			log.Fatal(err)
		}
		defer source.Close()

		describe(source)
	}
}

func describe(source identity.Source) {
	cert, err := source.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}
	leaf := cert.Leaf

	fmt.Printf("\n%s\n", path.Base(source.SPIFFEID()))
	fmt.Printf("  identity   : %s   (Source.SPIFFEID)\n", source.SPIFFEID())
	fmt.Printf("  URI SAN    : %s   (read back off the certificate)\n", leaf.URIs[0])
	// Empty on purpose, and worth pointing at: the identity is the URI SAN
	// above, never the subject that a normal TLS certificate would use.
	fmt.Printf("  subject    : %q   (empty: identity does not live here)\n", leaf.Subject.String())
	fmt.Printf("  issuer     : %s\n", leaf.Issuer.CommonName)
	fmt.Printf("  serial     : %x\n", leaf.SerialNumber)
	fmt.Printf("  key        : %s\n", leaf.PublicKeyAlgorithm)
	fmt.Printf("  signature  : %s\n", leaf.SignatureAlgorithm)
	fmt.Printf("  valid for  : %s (until %s)\n",
		time.Until(leaf.NotAfter).Round(time.Minute),
		leaf.NotAfter.Format(time.RFC3339))
	fmt.Printf("  usable as  : %s\n", extKeyUsages(leaf))
}

func extKeyUsages(cert *x509.Certificate) string {
	names := make([]string, 0, len(cert.ExtKeyUsage))
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "client")
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "server")
		}
	}
	return fmt.Sprint(names)
}
