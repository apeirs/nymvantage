package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/apeirs/nymvantage/internal/fakes"
	"github.com/apeirs/nymvantage/nym"
)

func run(t *testing.T, f func(context.Context, []string, interface{ Write([]byte) (int, error) }, interface{ Write([]byte) (int, error) }, *common) int, c *common, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code := f(ctx, args, &out, &errb, c)
	return code, out.String() + errb.String()
}

func tlsCmd(ctx context.Context, a []string, o, e interface{ Write([]byte) (int, error) }, c *common) int {
	return runTLSWith(ctx, a, o, e, c)
}
func sshCmd(ctx context.Context, a []string, o, e interface{ Write([]byte) (int, error) }, c *common) int {
	return runSSHWith(ctx, a, o, e, c)
}
func getCmd(ctx context.Context, a []string, o, e interface{ Write([]byte) (int, error) }, c *common) int {
	return runGetWith(ctx, a, o, e, c)
}

func caFile(t *testing.T, ca *fakes.CA) string {
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, ca.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// proxies starts n fake Nym SOCKS5 clients, each routing target to the
// matching address in to.
func proxies(t *testing.T, target string, to ...string) []string {
	var out []string
	for _, addr := range to {
		s := fakes.NewSOCKS(map[string]string{target: addr})
		t.Cleanup(s.Close)
		out = append(out, "--proxy", s.Addr)
	}
	return out
}

func deadProxies(n int) []string {
	var out []string
	for i := range n {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := ln.Addr().String()
		ln.Close() // nothing listens there now
		_ = i
		out = append(out, "--proxy", addr)
	}
	return out
}

func TestTLSVerdicts(t *testing.T) {
	ca, evil := fakes.NewCA(), fakes.NewCA()
	var goodHits, mitmHits fakes.Counter
	good, stop1 := fakes.TLSServer(ca.Leaf("server.test"), nil, &goodHits)
	defer stop1()
	good2, stop2 := fakes.TLSServer(ca.Leaf("server.test"), nil, nil) // same CA, another certificate (a CDN edge)
	defer stop2()
	mitm, stop3 := fakes.TLSServer(evil.Leaf("server.test"), nil, &mitmHits)
	defer stop3()
	wrong, stop4 := fakes.TLSServer(ca.Leaf("other.test"), nil, nil) // same CA, not valid for the name
	defer stop4()
	cf := caFile(t, ca)
	base := []string{"--ca-file", cf, "--sni", "server.test"}

	// Your connection reaches the real server and so do the mixnet paths.
	code, out := run(t, tlsCmd, &common{}, append(append(base, "--local", good), proxies(t, good, good, good, good)...)...)
	if code != 0 || !strings.Contains(out, "verdict: MATCH (compared by certificate)") {
		t.Fatalf("all good: exit %d\n%s", code, out)
	}

	// Your connection is intercepted: the "server" you reach directly is the
	// MITM box, while the mixnet paths reach the real one.
	code, out = run(t, tlsCmd, &common{}, append(append(base, "--local", mitm), proxies(t, mitm, good, good, good)...)...)
	if code != 1 || !strings.Contains(out, "verdict: MISMATCH") || !strings.Contains(out, "the CA that issued it differs") {
		t.Fatalf("intercepted: exit %d\n%s", code, out)
	}

	// One exit (or the server, for one visitor) shows something else.
	code, out = run(t, tlsCmd, &common{}, append(append(base, good), proxies(t, good, good, mitm, good)...)...)
	if code != 1 || !strings.Contains(out, "verdict: SPLIT") || !strings.Contains(out, "NOT TRUSTED") {
		t.Fatalf("split: exit %d\n%s", code, out)
	}

	// A CDN: two certificates from the same CA, both trusted.
	code, out = run(t, tlsCmd, &common{}, append(append(base, good), proxies(t, good, good, good2, good)...)...)
	if code != 0 || !strings.Contains(out, "AGREE (compared by issuing CA)") || !strings.Contains(out, "normal for CDNs") {
		t.Fatalf("cdn: exit %d\n%s", code, out)
	}
	code, out = run(t, tlsCmd, &common{}, append(append(base, "--strict", good), proxies(t, good, good, good2, good)...)...)
	if code != 1 || !strings.Contains(out, "verdict: SPLIT") {
		t.Fatalf("cdn --strict: exit %d\n%s", code, out)
	}
	// The same broken certificate everywhere: consistent, and said so.
	code, out = run(t, tlsCmd, &common{}, append([]string{"--ca-file", cf, "--sni", "server.test", wrong}, proxies(t, wrong, wrong, wrong, wrong)...)...)
	if code != 0 || !strings.Contains(out, "problem of the server itself") {
		t.Fatalf("broken cert everywhere: exit %d\n%s", code, out)
	}
	// Same CA, but one certificate is not valid for the name: never "normal".
	code, out = run(t, tlsCmd, &common{}, append(append(base, good), proxies(t, good, good, wrong, good)...)...)
	if code != 1 || !strings.Contains(out, "verdict: SPLIT") || strings.Contains(out, "normal for CDNs") {
		t.Fatalf("same CA, wrong name: exit %d\n%s", code, out)
	}
}

func TestFailsClosed(t *testing.T) {
	ca := fakes.NewCA()
	var hits fakes.Counter
	good, stop := fakes.TLSServer(ca.Leaf("server.test"), []byte("x"), &hits)
	defer stop()
	srv := fakes.NewSSHServer(fakes.HostKeys("ed25519"))
	defer srv.Close()
	cf := caFile(t, ca)
	for name, args := range map[string][]string{
		"tls": append([]string{"tls", "--ca-file", cf, good}, deadProxies(3)...),
		"ssh": append([]string{"ssh", "--known-hosts", "", srv.Addr}, deadProxies(3)...),
		"get": append([]string{"get", "--ca-file", cf, "https://" + good + "/f"}, deadProxies(3)...),
	} {
		f := map[string]func(context.Context, []string, interface{ Write([]byte) (int, error) }, interface{ Write([]byte) (int, error) }, *common) int{"tls": tlsCmd, "ssh": sshCmd, "get": getCmd}[args[0]]
		code, out := run(t, f, &common{}, args[1:]...)
		if code != 2 || !strings.Contains(out, "INCONCLUSIVE") || !strings.Contains(out, "refusing to fall back to a direct connection") {
			t.Errorf("%s with no Nym client: exit %d\n%s", name, code, out)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if hits.N() != 0 || srv.Conns.N() != 0 {
		t.Fatalf("targets contacted directly: tls/get %d, ssh %d", hits.N(), srv.Conns.N())
	}
}

// A vantage point that accepts the connection and then never answers costs
// --probe-timeout, not the whole --timeout.
func TestProbeTimeout(t *testing.T) {
	ca := fakes.NewCA()
	good, stop := fakes.TLSServer(ca.Leaf("server.test"), nil, nil)
	defer stop()
	hang, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hang.Close()
	go func() {
		for {
			c, err := hang.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold it open, say nothing
		}
	}()
	s := fakes.NewSOCKS(map[string]string{good: hang.Addr().String()})
	defer s.Close()
	t0 := time.Now()
	args := append([]string{"--ca-file", caFile(t, ca), "--sni", "server.test", "--probe-timeout", "300ms", good, "--proxy", s.Addr}, proxies(t, good, good, good, good)...)
	code, out := run(t, tlsCmd, &common{}, args...)
	if code != 0 || time.Since(t0) > 5*time.Second || !strings.Contains(out, "all 3 mixnet vantage points that answered") {
		t.Fatalf("exit %d after %s\n%s", code, time.Since(t0), out)
	}
}

func TestQuorum(t *testing.T) {
	ca := fakes.NewCA()
	good, stop := fakes.TLSServer(ca.Leaf("server.test"), nil, nil)
	defer stop()
	args := append([]string{"--ca-file", caFile(t, ca), "--sni", "server.test", good}, proxies(t, good, good)...)
	args = append(args, deadProxies(2)...)
	code, out := run(t, tlsCmd, &common{}, args...)
	if code != 2 || !strings.Contains(out, "only 1 of 3") {
		t.Fatalf("1 of 3 answering must be inconclusive: exit %d\n%s", code, out)
	}
	code, out = run(t, tlsCmd, &common{}, append(args, "--quorum", "1")...)
	if code != 0 {
		t.Fatalf("--quorum 1: exit %d\n%s", code, out)
	}
}

func TestSSHKnownHosts(t *testing.T) {
	keys := fakes.HostKeys("ed25519", "ecdsa")
	srv := fakes.NewSSHServer(keys)
	defer srv.Close()
	other := fakes.NewSSHServer(fakes.HostKeys("ed25519", "ecdsa"))
	defer other.Close()
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, []byte("# empty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	px := func(to ...string) []string { return proxies(t, "git.test:22", to...) }

	code, out := run(t, sshCmd, &common{}, append([]string{"git.test", "--known-hosts", kh}, px(srv.Addr, srv.Addr, srv.Addr)...)...)
	if code != 0 || !strings.Contains(out, "verdict: AGREE") || strings.Count(out, "\n  git.test ") != 2 {
		t.Fatalf("new host: exit %d\n%s", code, out)
	}
	if srv.AuthTries.Load() != 0 {
		t.Fatal("authentication attempted")
	}

	code, out = run(t, sshCmd, &common{}, append([]string{"git.test", "--known-hosts", kh, "--add"}, px(srv.Addr, srv.Addr, srv.Addr)...)...)
	if code != 0 || !strings.Contains(out, "added 2 line(s)") {
		t.Fatalf("--add: exit %d\n%s", code, out)
	}
	cb, err := knownhosts.New(kh)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if err := cb("git.test:22", &net.TCPAddr{IP: net.IPv4zero, Port: 22}, k.PublicKey()); err != nil {
			t.Fatalf("added line does not verify for ssh(1): %v", err)
		}
	}

	code, out = run(t, sshCmd, &common{}, append([]string{"git.test", "--known-hosts", kh}, px(srv.Addr, srv.Addr, srv.Addr)...)...)
	if code != 0 || !strings.Contains(out, "verdict: MATCH") || !strings.Contains(out, "known_hosts MATCH") || strings.Contains(out, "--add appends") {
		t.Fatalf("known host: exit %d\n%s", code, out)
	}

	// The server's key is no longer what you stored (a re-installed server,
	// or the one you trusted was a man in the middle): every vantage sees the
	// other key.
	before, _ := os.ReadFile(kh)
	code, out = run(t, sshCmd, &common{}, append([]string{"git.test", "--known-hosts", kh, "--add"}, px(other.Addr, other.Addr, other.Addr)...)...)
	if code != 1 || !strings.Contains(out, "known_hosts MISMATCH") {
		t.Fatalf("changed key: exit %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(kh); !bytes.Equal(before, after) {
		t.Fatal("--add wrote to known_hosts on a mismatch")
	}

	// One vantage point is shown another key.
	code, out = run(t, sshCmd, &common{}, append([]string{"git.test", "--known-hosts", ""}, px(srv.Addr, other.Addr, srv.Addr)...)...)
	if code != 1 || !strings.Contains(out, "SPLIT") || strings.Contains(out, "known_hosts lines") {
		t.Fatalf("split: exit %d\n%s", code, out)
	}
	// One vantage point is missing a key type the others see.
	edOnly := fakes.NewSSHServer(keys[:1])
	defer edOnly.Close()
	code, out = run(t, sshCmd, &common{}, append([]string{"git.test", "--known-hosts", ""}, px(srv.Addr, srv.Addr, edOnly.Addr)...)...)
	if code != 1 || !strings.Contains(out, "ecdsa-sha2-nistp256  SPLIT") || strings.Contains(out, "\n  git.test ") {
		t.Fatalf("missing type: exit %d\n%s", code, out)
	}
}

// An exit that drops out after the first handshake gives no answer for the
// other key types; that must not look like "the server has no such key".
func TestSSHFailedTypeIsNoAnswer(t *testing.T) {
	srv := fakes.NewSSHServer(fakes.HostKeys("ed25519", "ecdsa"))
	defer srv.Close()
	args := []string{"git.test", "--known-hosts", ""}
	for i := range 3 {
		s := fakes.NewSOCKS(map[string]string{"git.test:22": srv.Addr})
		defer s.Close()
		if i == 2 {
			s.FailAfter(1)
		}
		args = append(args, "--proxy", s.Addr)
	}
	code, out := run(t, sshCmd, &common{}, args...)
	if code != 0 || strings.Contains(out, "SPLIT") || !strings.Contains(out, "ecdsa-sha2-nistp256  AGREE") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestSSHHashedAdd(t *testing.T) {
	srv := fakes.NewSSHServer(fakes.HostKeys("ed25519"))
	defer srv.Close()
	kh := filepath.Join(t.TempDir(), "kh")
	code, out := run(t, sshCmd, &common{}, append([]string{"git.test:2222", "--known-hosts", kh, "--add", "--hash"}, proxies(t, "git.test:2222", srv.Addr, srv.Addr)...)...)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	b, _ := os.ReadFile(kh)
	if !strings.HasPrefix(string(b), "|1|") || strings.Contains(string(b), "git.test") {
		t.Fatalf("not hashed: %s", b)
	}
	cb, _ := knownhosts.New(kh)
	var pub ssh.PublicKey
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		_, _, pub, _, _, _ = ssh.ParseKnownHosts([]byte(l))
	}
	if err := cb("git.test:2222", &net.TCPAddr{IP: net.IPv4zero, Port: 2222}, pub); err != nil {
		t.Fatalf("hashed non-default-port line: %v", err)
	}
}

func TestGet(t *testing.T) {
	ca := fakes.NewCA()
	real, stop1 := fakes.TLSServer(ca.Leaf("dl.test"), []byte("abc123  release.tar.gz\n"), nil)
	defer stop1()
	evil, stop2 := fakes.TLSServer(ca.Leaf("dl.test"), []byte("666666  release.tar.gz\n"), nil)
	defer stop2()
	cf := caFile(t, ca)
	dir := t.TempDir()
	dst := filepath.Join(dir, "SHA256SUMS")
	px := func(to ...string) []string { return proxies(t, "dl.test:443", to...) }

	code, out := run(t, getCmd, &common{}, append([]string{"--ca-file", cf, "-o", dst, "https://dl.test/SHA256SUMS"}, px(real, real, real)...)...)
	if b, _ := os.ReadFile(dst); code != 0 || string(b) != "abc123  release.tar.gz\n" {
		t.Fatalf("agree: exit %d, file %q\n%s", code, b, out)
	}
	os.Remove(dst)

	// A targeted download: one visitor gets a different file.
	code, out = run(t, getCmd, &common{}, append([]string{"--ca-file", cf, "-o", dst, "https://dl.test/SHA256SUMS"}, px(real, evil, real)...)...)
	if _, err := os.Stat(dst); code != 1 || err == nil || !strings.Contains(out, "not saved") {
		t.Fatalf("split must not save: exit %d\n%s", code, out)
	}

	code, out = run(t, getCmd, &common{}, append([]string{"--ca-file", cf, "-o", dst, "--expect", strings.Repeat("ab", 32), "https://dl.test/SHA256SUMS"}, px(real, real, real)...)...)
	if _, err := os.Stat(dst); code != 1 || err == nil || !strings.Contains(out, "MISMATCH") {
		t.Fatalf("--expect wrong: exit %d\n%s", code, out)
	}

	code, out = run(t, getCmd, &common{}, append([]string{"--ca-file", cf, "https://dl.test/missing"}, px(real, real, real)...)...)
	if code != 2 || !strings.Contains(out, "HTTP 404") {
		t.Fatalf("404 everywhere is not agreement: exit %d\n%s", code, out)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("left files behind: %v", entries)
	}
}

// The default path: new throwaway clients, one exit each.
func TestEphemeralVantagesUseDistinctExits(t *testing.T) {
	ca := fakes.NewCA()
	good, stop := fakes.TLSServer(ca.Leaf("server.test"), nil, nil)
	defer stop()
	var ps []nym.ExitProvider
	for i := range 8 {
		ps = append(ps, nym.ExitProvider{NodeID: 100 + i, Country: string(rune('A'+i)) + "Q", Address: "nr"})
	}
	var mu sync.Mutex
	started, closed := map[int]bool{}, 0
	c := &common{
		providers: ps,
		starter: func(_ context.Context, p nym.ExitProvider) (string, func(), error) {
			s := fakes.NewSOCKS(map[string]string{"server.test:443": good})
			mu.Lock()
			started[p.NodeID] = true
			mu.Unlock()
			return s.Addr, func() { s.Close(); mu.Lock(); closed++; mu.Unlock() }, nil
		},
	}
	code, out := run(t, tlsCmd, c, "--ca-file", caFile(t, ca), "-n", "4", "server.test")
	if code != 0 || !strings.Contains(out, "4 vantage points through the Nym mixnet") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if len(started) != 4 || closed != 4 {
		t.Fatalf("started %v, closed %d: want 4 distinct exits, all stopped", started, closed)
	}
}

func TestUsage(t *testing.T) {
	if code, _ := run(t, tlsCmd, &common{}); code != 3 {
		t.Error("no host")
	}
	if code, _ := run(t, getCmd, &common{}, "http://plain.test/x"); code != 3 {
		t.Error("http:// accepted")
	}
	if code, _ := run(t, getCmd, &common{}, "--expect", "zz", "https://x.test/"); code != 3 {
		t.Error("bad --expect")
	}
	h, p, err := splitHostPort("[2001:db8::1]:2222", 22)
	if err != nil || h != "2001:db8::1" || p != 2222 {
		t.Error(h, p, err)
	}
	if h, p, _ := splitHostPort("example.org", 443); h != "example.org" || p != 443 {
		t.Error(h, p)
	}
}

func TestClientsHoldsUntilInterrupted(t *testing.T) {
	var mu sync.Mutex
	closed := 0
	ps := []nym.ExitProvider{{NodeID: 1, Country: "AA"}, {NodeID: 2, Country: "BB"}, {NodeID: 3, Country: "CC"}}
	c := &common{providers: ps, starter: func(_ context.Context, p nym.ExitProvider) (string, func(), error) {
		return fmt.Sprintf("127.0.0.1:%d", 1000+p.NodeID), func() { mu.Lock(); closed++; mu.Unlock() }, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuf
	done := make(chan int)
	go func() { done <- runClientsWith(ctx, []string{"-n", "2"}, &out, &out, c) }()
	for i := 0; !strings.Contains(out.String(), "Use them with:") && i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	early := closed
	mu.Unlock()
	if early != 0 || strings.Count(out.String(), "--proxy 127.0.0.1:100") != 2 {
		t.Fatalf("closed %d before Ctrl-C\n%s", early, out.String())
	}
	cancel()
	if code := <-done; code != 0 || closed != 2 {
		t.Fatalf("exit %d, closed %d", code, closed)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
