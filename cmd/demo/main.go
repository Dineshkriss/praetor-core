// Command demo starts one mutually-authenticated service and makes four calls
// against it: one that should get through and three that should not.
//
// Nothing here is staged. Every rejection printed below is a real TLS handshake
// failure or a real identity check, and the demo exits non-zero if any call
// does the opposite of what it says it will.
//
//	go run ./cmd/demo
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
	paymentsID  = "spiffe://corp.example/ns/prod/sa/payments"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// One trust domain. In deployment this CA is SPIRE.
	ca, err := devca.New(trustDomain)
	if err != nil {
		return err
	}
	ordersIdentity, err := identityFor(ca, "/ns/prod/sa/orders")
	if err != nil {
		return err
	}
	defer ordersIdentity.Close()

	gatewayIdentity, err := identityFor(ca, "/ns/prod/sa/gateway")
	if err != nil {
		return err
	}
	defer gatewayIdentity.Close()

	ordersAddr, shutdown, err := startOrdersService(ordersIdentity)
	if err != nil {
		return err
	}
	defer shutdown()
	ordersURL := "https://" + ordersAddr + "/orders"

	fmt.Printf("orders service listening on %s as %s\n\n", ordersAddr, ordersIdentity.SPIFFEID())

	// 1. The intended call. Valid SVID on both ends, and the gateway is
	//    talking to exactly the service it asked for.
	gatewayClient, err := transport.ClientTo(gatewayIdentity, ordersID)
	if err != nil {
		return err
	}
	attempt(1, "gateway to orders, both hold valid SVIDs", expectAllowed,
		func() (string, error) { return get(gatewayClient, ordersURL) })

	// 2. No certificate at all. This is any unauthenticated process that has
	//    managed to get onto the network, and it is the baseline case the
	//    library exists to close.
	attempt(2, "caller presents no certificate", expectBlocked,
		func() (string, error) { return get(rawClient(nil), ordersURL) })

	// 3. The one to point at in the review. This certificate is genuine,
	//    well-formed, and claims the same SPIFFE ID as a real service. It
	//    fails on exactly one thing: it was signed by a CA we do not trust.
	untrustedCA, err := devca.New("attacker.example")
	if err != nil {
		return err
	}
	forgedSVID, err := untrustedCA.Issue("/ns/prod/sa/gateway")
	if err != nil {
		return err
	}
	attempt(3, "caller's SVID is signed by an untrusted CA", expectBlocked, func() (string, error) {
		return get(rawClient(&tls.Certificate{
			Certificate: [][]byte{forgedSVID.Chain[0].Raw},
			PrivateKey:  forgedSVID.Key,
		}), ordersURL)
	})

	// 4. A perfectly legitimate caller that reached the wrong service. Orders
	//    is fully trusted, it is simply not who this client asked for, so the
	//    request is never sent.
	clientExpectingPayments, err := transport.ClientTo(gatewayIdentity, paymentsID)
	if err != nil {
		return err
	}
	attempt(4, "gateway expects payments but reaches orders", expectBlocked,
		func() (string, error) { return get(clientExpectingPayments, ordersURL) })

	return nil
}

// identityFor issues an SVID and wraps it as an identity source.
//
// Swapping this one call for identity.NewSPIRESource is the entire change
// needed to run against a real SPIRE agent. Everything else stays as it is.
func identityFor(ca *devca.CA, path string) (*identity.StaticSource, error) {
	svid, err := ca.Issue(path)
	if err != nil {
		return nil, err
	}
	return identity.NewStaticSource(svid.Chain, svid.Key, ca.TrustBundle())
}

// startOrdersService listens on a free loopback port. Its handler only ever
// sees requests whose caller is already proven.
func startOrdersService(self identity.Source) (addr string, shutdown func(), err error) {
	router := http.NewServeMux()
	router.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		callerID, ok := transport.PeerID(r)
		if !ok {
			// Belt and braces. Reaching this would mean the TLS config was
			// wrong, because an unverified caller cannot get this far.
			http.Error(w, "no verified peer identity", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "served to %s", callerID)
	})

	server, err := transport.NewServer("", router, self, transport.AllowAnyTrustedPeer())
	if err != nil {
		return "", nil, err
	}

	// Label the server's own handshake errors. They are the other half of the
	// evidence: the TLS stack logging each rejection as it makes it.
	server.ErrorLog = log.New(os.Stdout, "   [orders] ", 0)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	// Empty filenames: the certificate comes from the identity source at
	// handshake time, never from a file.
	go server.ServeTLS(listener, "", "")

	return listener.Addr().String(), func() { server.Close() }, nil
}

// rawClient is a hand-built TLS client for the negative cases. It skips server
// verification on purpose, so that every failure shown is the server rejecting
// the caller and not the other way round.
func rawClient(clientCert *tls.Certificate) *http.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   5 * time.Second,
	}
}

func get(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
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
	expectAllowed = true
	expectBlocked = false
)

// attempt runs one call, prints what happened, and kills the demo if the
// outcome contradicts the label. The demo cannot narrate a result it did not
// actually produce.
func attempt(step int, description string, wantAllowed bool, makeCall func() (string, error)) {
	fmt.Printf("%d. %s\n", step, description)
	body, err := makeCall()

	switch {
	case err == nil && wantAllowed:
		fmt.Printf("   ALLOWED, as expected. Response: %s\n\n", body)
	case err != nil && !wantAllowed:
		fmt.Printf("   BLOCKED, as expected: %v\n\n", err)
	case err != nil:
		fmt.Printf("   UNEXPECTED FAILURE: %v\n\n", err)
		os.Exit(1)
	default:
		fmt.Printf("   UNEXPECTEDLY ALLOWED: %s\n\n", body)
		os.Exit(1)
	}
}
