package mixnet

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// A cancelled request is reported as cancelled, not as "no SOCKS5 proxy".
func TestCancelIsNotProxyUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dialSocks(ctx, ln.Addr().String(), "1.2.3.4", 443, time.Second)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrProxyUnreachable) {
		t.Fatalf("got %v", err)
	}
	ln.Close()
	_, err = dialSocks(context.Background(), ln.Addr().String(), "1.2.3.4", 443, time.Second)
	if !errors.Is(err, ErrProxyUnreachable) {
		t.Fatalf("dead proxy: %v", err)
	}
}

func TestEncodeAddrAndParse(t *testing.T) {
	if b, _ := EncodeAddr("dns.quad9.net"); b[0] != 3 || b[1] != 13 || string(b[2:]) != "dns.quad9.net" {
		t.Fatalf("domain: %v", b)
	}
	if b, _ := EncodeAddr("1.2.3.4"); len(b) != 5 || b[0] != 1 {
		t.Fatalf("ipv4: %v", b)
	}
	if b, _ := EncodeAddr("::1"); len(b) != 17 || b[0] != 4 {
		t.Fatalf("ipv6: %v", b)
	}
	if p, _ := ParseProxy("socks5h://127.0.0.1"); p != "127.0.0.1:1080" {
		t.Fatal(p)
	}

}
