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

// The intended path: two workloads in one trust domain, each proving itself to
// the other, with the handler reading the caller's identity off the connection.
func TestMutualTLSRoundTrip(t *testing.T) {
	env := newEnv(t)
	client, err := transport.ClientTo(env.gateway, ordersID)
	if err != nil {
		t.Fatalf("ClientTo: %v", err)
	}

	body, err := get(client, env.url)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if want := "peer=" + env.gateway.SPIFFEID(); body != want {
		t.Errorf("handler saw %q, want %q", body, want)
	}
}

// Without a client certificate there is nothing to authenticate, so the
// handshake has to fail before any handler runs.
func TestServerRejectsCallerWithoutCertificate(t *testing.T) {
	env := newEnv(t)
	if _, err := get(rawClient(t, nil), env.url); err == nil {
		t.Fatal("expected the handshake to fail without a client certificate")
	}
}

// The rogue SVID is well formed and carries a valid SPIFFE ID. It fails purely
// because its chain does not terminate in our trust bundle, which is the check
// that makes a stolen or self-minted certificate useless.
func TestServerRejectsUntrustedIssuer(t *testing.T) {
	env := newEnv(t)
	rogue, err := devca.New("attacker.example")
	if err != nil {
		t.Fatalf("devca.New: %v", err)
	}
	svid, err := rogue.Issue("/ns/prod/sa/gateway")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	cert := &tls.Certificate{Certificate: [][]byte{svid.Chain[0].Raw}, PrivateKey: svid.Key}
	if _, err := get(rawClient(t, cert), env.url); err == nil {
		t.Fatal("expected an SVID from an untrusted CA to be rejected")
	}
}

// Pinning the callee means a trusted but unintended peer is still refused. The
// server here is perfectly valid, it is simply not the one the caller meant.
func TestClientRejectsUnexpectedServerIdentity(t *testing.T) {
	env := newEnv(t)
	client, err := transport.ClientTo(env.gateway, paymentsID)
	if err != nil {
		t.Fatalf("ClientTo: %v", err)
	}
	if _, err := get(client, env.url); err == nil {
		t.Fatal("expected the client to reject a server it did not ask for")
	}
}

// After rotation the source hands out a new certificate and the client keeps
// working, which is the property that lets SVIDs stay short lived.
func TestRotatedSVIDStillHandshakes(t *testing.T) {
	env := newEnv(t)
	client, err := transport.ClientTo(env.gateway, ordersID)
	if err != nil {
		t.Fatalf("ClientTo: %v", err)
	}
	if _, err := get(client, env.url); err != nil {
		t.Fatalf("request before rotation: %v", err)
	}

	next, err := env.ca.Issue("/ns/prod/sa/gateway")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := env.gateway.Rotate(next.Chain, next.Key); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if _, err := get(client, env.url); err != nil {
		t.Fatalf("request after rotation: %v", err)
	}
}

// PeerID must not report an identity for a request that did not arrive over
// verified mutual TLS, because a handler uses it to decide what to serve.
func TestPeerIDIsAbsentWithoutTLS(t *testing.T) {
	if id, ok := transport.PeerID(httptest.NewRequest(http.MethodGet, "/orders", nil)); ok {
		t.Fatalf("expected no peer identity on a plain request, got %q", id)
	}
}

type env struct {
	ca      *devca.CA
	gateway *identity.Static
	url     string
}

// newEnv brings up an orders server and a gateway identity in one trust domain.
func newEnv(t *testing.T) *env {
	t.Helper()
	ca, err := devca.New("corp.example")
	if err != nil {
		t.Fatalf("devca.New: %v", err)
	}
	orders := source(t, ca, "/ns/prod/sa/orders")
	gateway := source(t, ca, "/ns/prod/sa/gateway")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := transport.PeerID(r)
		if !ok {
			http.Error(w, "no verified peer", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "peer=%s", peer)
	})

	// A real listener rather than httptest.NewUnstartedServer: httptest injects
	// its own self-signed certificate into the config, which would then be
	// served instead of the SVID whenever the client connects without SNI.
	srv, err := transport.NewServer("", handler, orders, transport.AllowAnyInBundle())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })

	return &env{ca: ca, gateway: gateway, url: "https://" + ln.Addr().String() + "/orders"}
}

func source(t *testing.T, ca *devca.CA, path string) *identity.Static {
	t.Helper()
	svid, err := ca.Issue(path)
	if err != nil {
		t.Fatalf("devca issue %s: %v", path, err)
	}
	src, err := identity.NewStatic(svid.Chain, svid.Key, ca.Roots())
	if err != nil {
		t.Fatalf("NewStatic: %v", err)
	}
	t.Cleanup(func() { src.Close() })
	return src
}

// rawClient skips server verification so that a failed call is unambiguously
// the server rejecting this caller.
func rawClient(t *testing.T, cert *tls.Certificate) *http.Client {
	t.Helper()
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	rt := &http.Transport{TLSClientConfig: cfg}
	t.Cleanup(rt.CloseIdleConnections)
	return &http.Client{Transport: rt}
}

func get(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
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
