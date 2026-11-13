package vantage

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/apeirs/nymvantage/nym"
)

func providers(n int) []nym.ExitProvider {
	var ps []nym.ExitProvider
	for i := range n {
		ps = append(ps, nym.ExitProvider{NodeID: i + 1, Country: string(rune('A'+i)) + "X", Address: "nr" + string(rune('a'+i))})
	}
	return ps
}

// fakeStarter records which exits were started and fails for those in bad.
type fakeStarter struct {
	mu      sync.Mutex
	started []int
	closed  []int
	bad     map[int]bool
}

func (f *fakeStarter) start(_ context.Context, p nym.ExitProvider) (string, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, p.NodeID)
	if f.bad[p.NodeID] {
		return "", nil, errors.New("gateway did not answer")
	}
	id := p.NodeID
	return "127.0.0.1:1", func() { f.mu.Lock(); f.closed = append(f.closed, id); f.mu.Unlock() }, nil
}

func TestEphemeralDistinctExitsAndCleanup(t *testing.T) {
	f := &fakeStarter{}
	set, err := Ephemeral(context.Background(), providers(10), 3, 2, f.start, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 3 || len(set.Usable()) != 3 {
		t.Fatalf("set %d usable %d", len(set), len(set.Usable()))
	}
	labels := map[string]bool{}
	for _, v := range set {
		if !v.Mixnet || v.Dial == nil {
			t.Fatalf("%s: not a mixnet vantage", v.Name)
		}
		if labels[v.Label] {
			t.Fatalf("exit used twice: %s", v.Label)
		}
		labels[v.Label] = true
	}
	if len(f.started) != 3 {
		t.Errorf("started %v, want exactly 3 clients", f.started)
	}
	set.Close()
	set.Close() // twice is harmless
	if len(f.closed) < 3 {
		t.Errorf("closed %v: every client must be stopped", f.closed)
	}
}

func TestEphemeralReplacesAFailedClient(t *testing.T) {
	ps := providers(4) // 2 + 2 spares: every exit gets picked
	bad := map[int]bool{}
	for _, p := range ps[:3] {
		bad[p.NodeID] = true // only one exit works
	}
	f := &fakeStarter{bad: bad}
	set, err := Ephemeral(context.Background(), ps, 2, 2, f.start, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	if got := len(set.Usable()); got != 1 {
		t.Fatalf("usable %d, want 1 (one good exit)", got)
	}
	if len(f.started) != 4 {
		t.Errorf("started %v: want 2 + 2 spares, no more", f.started)
	}
	for _, v := range set {
		if v.Err == nil {
			continue
		}
		if v.Dial != nil {
			t.Error("a failed vantage must not be dialable")
		}
	}
}

func TestEphemeralTooFewExits(t *testing.T) {
	f := &fakeStarter{}
	if _, err := Ephemeral(context.Background(), providers(2), 3, 2, f.start, nil); err == nil {
		t.Fatal("3 vantage points from 2 exits must fail, not reuse an exit")
	}
}

func TestLocalIsOnlyExplicit(t *testing.T) {
	l := Local()
	if l.Mixnet || l.Name != "local" {
		t.Fatal("local vantage mislabelled")
	}
	set, _ := FromProxies([]string{"127.0.0.1:1", "socks5h://127.0.0.1:2"}, nil)
	for _, v := range set {
		if !v.Mixnet {
			t.Fatal("proxy vantage must be mixnet-only")
		}
	}
}
