// Package vantage provides the points of view nymvantage compares: several
// independent paths through the Nym mixnet, and (only when asked for) the
// user's own direct connection.
package vantage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/apeirs/nymvantage/mixnet"
	"github.com/apeirs/nymvantage/nym"
)

// DialFunc opens a TCP stream to "host:port".
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Vantage is one point of view.
type Vantage struct {
	Name   string // "nym-1", "proxy-1", "local"
	Label  string // human description: "exit node 2950 (CA)", "direct"
	Mixnet bool   // true for every path through the mixnet; false only for "local"
	Dial   DialFunc
	Proxy  string        // SOCKS5 address of the Nym client ("" for local)
	Err    error         // set when this vantage could not be set up
	Ready  time.Duration // how long setting it up took

	close func()
}

// Close releases the vantage (stops its Nym client and deletes its identity).
func (v *Vantage) Close() {
	if v.close != nil {
		f := v.close
		v.close = nil // stop each client once, however often Close is called
		f()
	}
}

// Set is the vantages of one check.
type Set []*Vantage

// Close releases every vantage.
func (s Set) Close() {
	for _, v := range s {
		v.Close()
	}
}

// Usable returns the vantages that were set up.
func (s Set) Usable() Set {
	var out Set
	for _, v := range s {
		if v.Err == nil {
			out = append(out, v)
		}
	}
	return out
}

// mixnetDialer wraps a SOCKS5 proxy address as a mixnet-only DialFunc.
func mixnetDialer(proxy string, trace mixnet.Tracer) DialFunc {
	d := &mixnet.Dialer{Proxy: proxy, Timeout: 60 * time.Second, Trace: trace}
	return d.DialContext
}

// FromProxies uses SOCKS5 proxies the user runs (one Nym client each). The
// tool cannot tell whether two proxies share an exit; the user is told so.
func FromProxies(proxies []string, trace mixnet.Tracer) (Set, error) {
	var s Set
	for i, p := range proxies {
		addr, err := mixnet.ParseProxy(p)
		if err != nil {
			return nil, err
		}
		s = append(s, &Vantage{
			Name:   fmt.Sprintf("proxy-%d", i+1),
			Label:  "Nym client " + addr,
			Mixnet: true,
			Dial:   mixnetDialer(addr, trace),
			Proxy:  addr,
		})
	}
	return s, nil
}

// Starter starts one throwaway Nym client for an exit (nym.StartEphemeral in
// production; a fake in tests).
type Starter func(ctx context.Context, p nym.ExitProvider) (proxy string, closeFn func(), err error)

// EphemeralStarter returns a Starter that runs the release nym-socks5-client.
func EphemeralStarter(binary, base string) Starter {
	return func(ctx context.Context, p nym.ExitProvider) (string, func(), error) {
		e, err := nym.StartEphemeral(ctx, binary, p, base)
		if err != nil {
			return "", nil, err
		}
		return e.Proxy, e.Close, nil
	}
}

// Ephemeral starts n throwaway Nym clients in parallel, each with a new
// mixnet identity and a different exit gateway (different countries where
// possible). A client that does not start is replaced by one on another exit,
// up to spares times in total. Vantages that still failed carry Err.
func Ephemeral(ctx context.Context, providers []nym.ExitProvider, n, spares int, start Starter, trace mixnet.Tracer) (Set, error) {
	picks, err := nym.PickDistinct(providers, min(n+spares, len(providers)))
	if err != nil {
		return nil, err
	}
	if len(picks) < n {
		return nil, fmt.Errorf("asked for %d vantage points, only %d exit gateways usable", n, len(picks))
	}
	main, extra := picks[:n], picks[n:]
	var mu sync.Mutex
	next := func() (nym.ExitProvider, bool) {
		mu.Lock()
		defer mu.Unlock()
		if len(extra) == 0 {
			return nym.ExitProvider{}, false
		}
		p := extra[0]
		extra = extra[1:]
		return p, true
	}
	set := make(Set, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int, p nym.ExitProvider) {
			defer wg.Done()
			v := &Vantage{Name: fmt.Sprintf("nym-%d", i+1), Mixnet: true}
			set[i] = v
			t0 := time.Now()
			var errs []error
			for {
				v.Label = exitLabel(p)
				sctx, cancel := context.WithTimeout(ctx, 90*time.Second)
				proxy, closeFn, err := start(sctx, p)
				cancel()
				if err == nil {
					v.Ready = time.Since(t0)
					v.Dial = mixnetDialer(proxy, trace)
					v.Proxy = proxy
					v.close = closeFn
					v.Err = nil
					return
				}
				errs = append(errs, fmt.Errorf("%s: %w", v.Label, err))
				v.Err = errors.Join(errs...)
				if ctx.Err() != nil {
					return
				}
				np, ok := next()
				if !ok {
					return
				}
				p = np
			}
		}(i, main[i])
	}
	wg.Wait()
	return set, nil
}

func exitLabel(p nym.ExitProvider) string {
	c := p.Country
	if c == "" {
		c = "?"
	}
	return fmt.Sprintf("exit node %d (%s)", p.NodeID, c)
}

// Local is the user's own direct connection. It exists only when the user
// asks for it (--local): it is the view being checked, never a fallback.
func Local() *Vantage {
	d := &net.Dialer{Timeout: 20 * time.Second}
	return &Vantage{Name: "local", Label: "your direct connection", Dial: d.DialContext}
}
