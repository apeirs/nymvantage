package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/apeirs/nymvantage/internal/fakes"
	"github.com/apeirs/nymvantage/mixnet"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func via(s *fakes.SOCKS) DialFunc {
	return (&mixnet.Dialer{Proxy: s.Addr, Timeout: 5 * time.Second}).DialContext
}

func TestTLSThroughProxyByName(t *testing.T) {
	ca := fakes.NewCA()
	addr, stop := fakes.TLSServer(ca.Leaf("server.test"), nil, nil)
	defer stop()
	s := fakes.NewSOCKS(map[string]string{"server.test:443": addr})
	defer s.Close()
	v, err := TLS(ctx(t), via(s), "server.test", 443, "server.test", ca.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Trusted || v.LeafSHA256 == "" || v.SPKISHA256 == "" || v.IssuerKeyID == "" {
		t.Fatalf("view %+v", v)
	}
	seen := s.Seen()
	if len(seen) != 1 || seen[0].ATYP != 3 || seen[0].Host != "server.test" {
		t.Fatalf("proxy saw %v: the name must go to the exit unresolved", seen)
	}
}

func TestTLSRecordsUntrustedCertificate(t *testing.T) {
	ca, evil := fakes.NewCA(), fakes.NewCA()
	addr, stop := fakes.TLSServer(evil.Leaf("server.test"), nil, nil)
	defer stop()
	s := fakes.NewSOCKS(map[string]string{"server.test:443": addr})
	defer s.Close()
	v, err := TLS(ctx(t), via(s), "server.test", 443, "server.test", ca.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if v.Trusted || v.TrustError == "" {
		t.Fatal("a certificate from an unknown CA must be recorded as not trusted")
	}
	w, _ := TLS(ctx(t), via(s), "server.test", 443, "other.test", evil.Pool)
	if w.Trusted {
		t.Fatal("name mismatch must not be trusted")
	}
}

func TestNoProxyNoFallback(t *testing.T) {
	var hits fakes.Counter
	ca := fakes.NewCA()
	ln := fakes.Listen(&hits)
	defer ln.Close()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	portN, _ := strconv.Atoi(ps)
	dead := (&mixnet.Dialer{Proxy: "127.0.0.1:1", Timeout: 2 * time.Second}).DialContext
	if _, err := TLS(ctx(t), dead, "127.0.0.1", portN, "x", ca.Pool); !errors.Is(err, mixnet.ErrProxyUnreachable) {
		t.Fatalf("tls: %v", err)
	}
	if _, err := SSH(ctx(t), dead, "127.0.0.1", portN, DefaultSSHAlgos); !errors.Is(err, mixnet.ErrProxyUnreachable) {
		t.Fatalf("ssh: %v", err)
	}
	if _, err := Get(ctx(t), dead, "https://127.0.0.1:"+ps+"/f", 1<<20, ca.Pool, t.TempDir()); !errors.Is(err, mixnet.ErrProxyUnreachable) {
		t.Fatalf("get: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if hits.N() != 0 {
		t.Fatalf("the target got %d direct connection(s) with the proxy down", hits.N())
	}
}

func TestSSHHostKeysWithoutAuth(t *testing.T) {
	keys := fakes.HostKeys("ed25519", "rsa") // no ecdsa
	srv := fakes.NewSSHServer(keys)
	defer srv.Close()
	s := fakes.NewSOCKS(map[string]string{"git.test:22": srv.Addr})
	defer s.Close()
	v, err := SSH(ctx(t), via(s), "git.test", 22, DefaultSSHAlgos)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Keys) != 2 || v.Keys["ssh-ed25519"] == nil || v.Keys["ssh-rsa"] == nil {
		t.Fatalf("keys %v", v.Keys)
	}
	if len(v.Errors) != 0 {
		t.Errorf("a missing key type is not an error: %v", v.Errors)
	}
	for _, k := range keys {
		pub := k.PublicKey()
		if got := v.Keys[pub.Type()]; got == nil || got.Authorized == "" || !strings.HasPrefix(got.Fingerprint, "SHA256:") {
			t.Fatalf("%s: %+v", pub.Type(), got)
		}
	}
	if v.Banner != "SSH-2.0-FakeSSH_1.0" {
		t.Errorf("banner %q", v.Banner)
	}
	if srv.AuthTries.Load() != 0 {
		t.Fatalf("%d authentication attempt(s): a host key check must stop before auth", srv.AuthTries.Load())
	}
	for _, r := range s.Seen() {
		if r.ATYP != 3 || r.Host != "git.test" {
			t.Fatalf("proxy saw %v", r)
		}
	}
}

func TestGetHashesAndCaps(t *testing.T) {
	ca := fakes.NewCA()
	body := []byte("SHA256SUMS: everyone gets this\n")
	addr, stop := fakes.TLSServer(ca.Leaf("dl.test"), body, nil)
	defer stop()
	s := fakes.NewSOCKS(map[string]string{"dl.test:443": addr})
	defer s.Close()
	dir := t.TempDir()
	v, err := Get(ctx(t), via(s), "https://dl.test/SHA256SUMS", 1<<20, ca.Pool, dir)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if v.Status != 200 || v.SHA256 != hex.EncodeToString(sum[:]) || v.Size != int64(len(body)) {
		t.Fatalf("%+v", v)
	}
	if _, err := Get(ctx(t), via(s), "https://dl.test/SHA256SUMS", 5, ca.Pool, dir); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size cap: %v", err)
	}
	if _, err := Get(ctx(t), via(s), "https://dl.test/redirect-http", 1<<20, ca.Pool, dir); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("plain-http redirect followed: %v", err)
	}
	if _, err := Get(ctx(t), via(s), "http://dl.test/x", 1<<20, ca.Pool, dir); err == nil {
		t.Fatal("http:// fetched")
	}
	if _, err := Get(ctx(t), via(s), "https://dl.test/SHA256SUMS", 1<<20, fakes.NewCA().Pool, dir); err == nil {
		t.Fatal("an untrusted certificate was accepted for a download")
	}
}

// Key types that were not asked for because time ran out are errors (no
// answer), never "the server has no such key".
func TestSSHTypesLeftWhenTimeRunsOut(t *testing.T) {
	srv := fakes.NewSSHServer(fakes.HostKeys("ed25519", "ecdsa", "rsa"))
	defer srv.Close()
	s := fakes.NewSOCKS(map[string]string{"git.test:22": srv.Addr})
	defer s.Close()
	c, cancel := context.WithCancel(ctx(t))
	defer cancel()
	n := 0
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if n++; n == 2 {
			cancel() // the deadline passes during the second handshake
			return nil, context.Canceled
		}
		return via(s)(ctx, network, addr)
	}
	v, err := SSH(c, dial, "git.test", 22, DefaultSSHAlgos)
	if err != nil {
		t.Fatal(err)
	}
	if v.Keys["ssh-ed25519"] == nil || v.Errors["ecdsa-sha2-nistp256"] == "" || v.Errors["ssh-rsa"] == "" {
		t.Fatalf("keys %v errors %v", v.Keys, v.Errors)
	}
}
