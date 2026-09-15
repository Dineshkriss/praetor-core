// Command demo brings up one mutually-authenticated service and makes four
// calls against it: one that should succeed and three that should not.
//
// Every rejection printed below is a real TLS handshake failure or a real
// identity check, not a hardcoded branch. Run it with: go run ./cmd/demo
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/praetor-auth/praetor-core/identity"
	"github.com/praetor-auth/praetor-core/internal/devca"
	"github.com/praetor-auth/praetor-core/transport"
)

const (
	trustDomain = "corp.example"
	ordersID    = "spiffe://corp.example/ns/prod/sa/orders"
	gatewayID   = "spiffe://corp.example/ns/prod/sa/gateway"
	paymentsID  = "spiffe://corp.example/ns/prod/sa/payments"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// One trust domain, signed by a dev CA standing in for SPIRE.
	ca, err := devca.New(trustDomain)
	if err != nil {
		return err
	}
	orders, err := sourceFor(ca, "/ns/prod/sa/orders")
	if err != nil {
		return err
	}
	defer orders.Close()
	gateway, err := sourceFor(ca, "/ns/prod/sa/gateway")
	if err != nil {
		return err
	}
	defer gateway.Close()

	addr, stop, err := serve(orders)
	if err != nil {
		return err
	}
	defer stop()
	url := "https://" + addr + "/orders"

	fmt.Printf("orders service listening on %s as %s\n\n", addr, orders.SPIFFEID())

	// 1. The intended call. The gateway holds a valid SVID and expects to be
	//    talking to orders, which is exactly what is on the other end.
	client, err := transport.ClientTo(gateway, ordersID)
	if err != nil {
		return err
	}
	attempt(1, "gateway to orders, both hold valid SVIDs", expectOK,
		func() (string, error) { return call(client, url) })

	// 2. A caller with no certificate at all. This is what an unauthenticated
	//    process inside the cluster looks like, and it is the baseline case
	//    the library has to close.
	attempt(2, "caller presents no certificate", expectFail,
		func() (string, error) { return call(rawClient(nil), url) })

	// 3. A caller holding a real, well-formed SVID signed by a CA we do not
	//    trust. The certificate parses and carries a valid SPIFFE ID: it fails
	//    only because the chain does not terminate in our trust bundle.
	rogue, err := devca.New("attacker.example")
	if err != nil {
		return err
	}
	rogueSVID, err := rogue.Issue("/ns/prod/sa/orders") // same path, wrong CA
	if err != nil {
		return err
	}
	attempt(3, "caller's SVID is signed by an untrusted CA", expectFail, func() (string, error) {
		return call(rawClient(&tls.Certificate{
			Certificate: [][]byte{rogueSVID.Chain[0].Raw},
			PrivateKey:  rogueSVID.Key,
		}), url)
	})

	// 4. A legitimate caller that reached the wrong workload. The gateway is
	//    pinned to payments, so even though orders is a fully trusted peer the
	//    client refuses to hand it the request.
	pinned, err := transport.ClientTo(gateway, paymentsID)
	if err != nil {
		return err
	}
	attempt(4, "gateway expects payments but reaches orders", expectFail,
		func() (string, error) { return call(pinned, url) })

	return nil
}

// sourceFor issues an SVID from the dev CA and wraps it as an identity source.
// Swapping this one line for identity.NewSPIRESource is the whole change needed
// to run against a real SPIRE agent.
func sourceFor(ca *devca.CA, path string) (*identity.Static, error) {
	svid, err := ca.Issue(path)
	if err != nil {
		return nil, err
	}
	return identity.NewStatic(svid.Chain, svid.Key, ca.Roots())
}

// serve starts the orders service on a free loopback port and returns its
// address. The handler only ever sees requests whose peer is already proven.
func serve(src identity.Source) (addr string, stop func(), err error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		peer, ok := transport.PeerID(r)
		if !ok {
			// Defence in depth. Reaching here would mean the TLS config was
			// misconfigured, because an unverified peer cannot get this far.
			http.Error(w, "no verified peer identity", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "served to %s", peer)
	})

	srv, err := transport.NewServer("", mux, src, transport.AllowAnyInBundle())
	if err != nil {
		return "", nil, err
	}
	// Label the server's own handshake errors. They are the other half of the
	// evidence: each rejection below is logged here by the TLS stack itself.
	srv.ErrorLog = log.New(os.Stdout, "   [orders] ", 0)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	// Empty file names: the certificate comes from the identity source at
	// handshake time, never from disk.
	go srv.ServeTLS(ln, "", "")

	return ln.Addr().String(), func() { srv.Close() }, nil
}

// rawClient is a deliberately unhelpful TLS client used for the negative cases.
// It skips server verification so that every failure shown is the server
// rejecting the caller, not the caller rejecting the server.
func rawClient(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   5 * time.Second,
	}
}

func call(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Status, body)
	}
	return string(body), nil
}

const (
	expectOK   = true
	expectFail = false
)

// attempt runs one call and prints what happened. It exits non-zero when a call
// does the opposite of what the demo claims it will, so the demo cannot quietly
// narrate a result it did not actually produce.
func attempt(n int, what string, wantOK bool, do func() (string, error)) {
	fmt.Printf("%d. %s\n", n, what)
	body, err := do()
	switch {
	case err == nil && wantOK:
		fmt.Printf("   ALLOWED, as expected. Response: %s\n\n", body)
	case err != nil && !wantOK:
		fmt.Printf("   BLOCKED, as expected: %v\n\n", err)
	case err != nil:
		fmt.Printf("   UNEXPECTED FAILURE: %v\n\n", err)
		os.Exit(1)
	default:
		fmt.Printf("   UNEXPECTEDLY ALLOWED: %s\n\n", body)
		os.Exit(1)
	}
}
