package mixnet

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Tracer receives one human-readable line per network step.
type Tracer func(format string, args ...any)

// Dialer opens TCP streams through the Nym mixnet (SOCKS5 to nym-socks5-client).
//
// It never resolves a name itself: every hostname is handed to the exit
// gateway as a name (SOCKS5 ATYP 3), so the local resolver is never asked.
type Dialer struct {
	Proxy   string        // host:port of nym-socks5-client
	Timeout time.Duration // SOCKS handshake timeout (mixnet round trips are slow)
	Trace   Tracer
}

func (d *Dialer) trace(format string, args ...any) {
	if d.Trace != nil {
		d.Trace(format, args...)
	}
}

func (d *Dialer) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return 60 * time.Second
}

// DialContext opens a TCP stream to addr ("host:port") through the mixnet.
// It has the signature net/http expects.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("mixnet: unsupported network %q", network)
	}
	host, port, err := splitPort(addr)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	conn, err := dialSocks(ctx, d.Proxy, host, port, d.timeout())
	if err != nil {
		d.trace("dial %s:%d over the mixnet failed after %.2fs: %v", host, port, time.Since(t0).Seconds(), err)
		return nil, err
	}
	d.trace("dial %s:%d: SOCKS5 stream through the mixnet open in %.2fs", host, port, time.Since(t0).Seconds())
	return conn, nil
}
