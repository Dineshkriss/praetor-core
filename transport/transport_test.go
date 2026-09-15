package transport_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetor-auth/praetor-core/identity"
	"github.com/praetor-auth/praetor-core/internal/devca"
	"github.com/praetor-auth/praetor-core/transport"
)

const (
	ordersID   = "spiffe://corp.example/ns/prod/sa/orders"
	paymentsID = "spiffe://corp.example/ns/prod/sa/payments"
)

// The happy path: two workloads in one trust domain prove themselves to each
// other, and the handler learns the caller's identity from the connection.
func TestMutualTLSRoundTrip(t *testing.T) {
	svc := newOrdersService(t)

	gatewayClient, err := transport.ClientTo(svc.gatewayIdentity, ordersID)
	if err != nil {
		t.Fatalf("ClientTo: %v", err)
	}
	body, err := get(gatewayClient, svc.url)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if want := "caller=" + svc.gatewayIdentity.SPIFFEID(); body != want {
		t.Errorf("handler saw %q, want %q", body, want)
	}
}

// No certificate means nothing to authenticate, so the handshake must fail
// before any handler runs.
func TestCallerWithoutCertificateIsRejected(t *testing.T) {
	svc := newOrdersService(t)

	if _, err := get(rawClient(t, nil), svc.url); err == nil {
		t.Fatal("expected the handshake to fail without a client certificate")
	}
}

// The important negative case. This SVID is genuine and carries a valid SPIFFE
// ID for a real service path. It fails on one thing only: the wrong issuer.
func TestCallerFromUntrustedCAIsRejected(t *testing.T) {
	svc := newOrdersService(t)

	untrustedCA, err := devca.New("attacker.example")
	if err != nil {
		t.Fatalf("devca.New: %v", err)
	}
	forgedSVID, err := untrustedCA.Issue("/ns/prod/sa/gateway")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	forgedCert := &tls.Certificate{
		Certificate: [][]byte{forgedSVID.Chain[0].Raw},
		PrivateKey:  forgedSVID.Key,
	}
	if _, err := get(rawClient(t, forgedCert), svc.url); err == nil {
		t.Fatal("expected an SVID from an untrusted CA to be rejected")
	}
}

// Naming the callee means a trusted but unintended peer is still refused. The
// server here is entirely valid, it is just not the one the client asked for.
func TestClientRejectsTheWrongServerIdentity(t *testing.T) {
	svc := newOrdersService(t)

	clientExpectingPayments, err := transport.ClientTo(svc.gatewayIdentity, paymentsID)
	if err != nil {
		t.Fatalf("ClientTo: %v", err)
	}
	if _, err := get(clientExpectingPayments, svc.url); err == nil {
		t.Fatal("expected the client to refuse a server it did not ask for")
	}
}

// Calls keep working across a rotation. This is the property that makes short
// SVID lifetimes practical.
func TestCallsSurviveAnSVIDRotation(t *testing.T) {
	svc := newOrdersService(t)

	gatewayClient, err := transport.ClientTo(svc.gatewayIdentity, ordersID)
	if err != nil {
		t.Fatalf("ClientTo: %v", err)
	}
	if _, err := get(gatewayClient, svc.url); err != nil {
		t.Fatalf("request before rotation: %v", err)
	}

	renewed, err := svc.ca.Issue("/ns/prod/sa/gateway")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := svc.gatewayIdentity.Rotate(renewed.Chain, renewed.Key); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if _, err := get(gatewayClient, svc.url); err != nil {
		t.Fatalf("request after rotation: %v", err)
	}
}

// A handler uses PeerID to decide what to serve, so it must never report an
// identity for a request that did not arrive over verified mutual TLS.
func TestPeerIDIsAbsentWithoutTLS(t *testing.T) {
	plainRequest := httptest.NewRequest(http.MethodGet, "/orders", nil)

	if callerID, ok := transport.PeerID(plainRequest); ok {
		t.Fatalf("expected no peer identity on a plain request, got %q", callerID)
	}
}

// ordersService is a running mutual-TLS service plus a gateway identity to call
// it with, both in one trust domain.
type ordersService struct {
	ca              *devca.CA
	gatewayIdentity *identity.StaticSource
	url             string
}

func newOrdersService(t *testing.T) *ordersService {
	t.Helper()
	ca, err := devca.New("corp.example")
	if err != nil {
		t.Fatalf("devca.New: %v", err)
	}
	ordersIdentity := identityFor(t, ca, "/ns/prod/sa/orders")
	gatewayIdentity := identityFor(t, ca, "/ns/prod/sa/gateway")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callerID, ok := transport.PeerID(r)
		if !ok {
			http.Error(w, "no verified peer", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "caller=%s", callerID)
	})

	server, err := transport.NewServer("", handler, ordersIdentity, transport.AllowAnyTrustedPeer())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// A real listener rather than httptest.NewUnstartedServer, which injects
	// its own self-signed certificate into the config. That certificate would
	// then be served instead of the SVID whenever a client connects without
	// SNI, which is exactly what happens when dialling an IP address.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go server.ServeTLS(listener, "", "")
	t.Cleanup(func() { server.Close() })

	return &ordersService{
		ca:              ca,
		gatewayIdentity: gatewayIdentity,
		url:             "https://" + listener.Addr().String() + "/orders",
	}
}

func identityFor(t *testing.T, ca *devca.CA, path string) *identity.StaticSource {
	t.Helper()
	svid, err := ca.Issue(path)
	if err != nil {
		t.Fatalf("devca issue %s: %v", path, err)
	}
	source, err := identity.NewStaticSource(svid.Chain, svid.Key, ca.TrustBundle())
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}
	t.Cleanup(func() { source.Close() })
	return source
}

// rawClient skips server verification so that a failed call is unambiguously
// the server rejecting this caller.
func rawClient(t *testing.T, clientCert *tls.Certificate) *http.Client {
	t.Helper()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}
	roundTripper := &http.Transport{TLSClientConfig: tlsConfig}
	t.Cleanup(roundTripper.CloseIdleConnections)
	return &http.Client{Transport: roundTripper}
}

func get(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Status, body)
	}
	return string(body), nil
}
