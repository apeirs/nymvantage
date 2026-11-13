package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultSSHAlgos are the host key algorithms asked for by default: one
// handshake each, like ssh-keyscan -t ed25519,ecdsa,rsa.
var DefaultSSHAlgos = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA512}

// AllSSHAlgos adds the rarer ECDSA curves.
var AllSSHAlgos = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512}

// SSHKey is one host key a server presented.
type SSHKey struct {
	Type        string        `json:"type"`        // ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa, ...
	Fingerprint string        `json:"fingerprint"` // SHA256:... as ssh(1) prints it
	Authorized  string        `json:"public_key"`  // "type base64", as in known_hosts
	Key         ssh.PublicKey `json:"-"`
}

// SSHView is what one vantage point was shown by an SSH server.
type SSHView struct {
	Banner string             `json:"banner"`
	Keys   map[string]*SSHKey `json:"keys"`             // by key type
	Errors map[string]string  `json:"errors,omitempty"` // by key type: asking for it failed (other than "server has no such key")
	Took   float64            `json:"seconds"`
}

var errGotKey = errors.New("host key recorded")

// bannerConn records the first line the server sends (its version string).
type bannerConn struct {
	net.Conn
	r      *bufio.Reader
	mu     sync.Mutex
	banner string
	seen   bool
	buf    []byte
}

func (c *bannerConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.mu.Lock()
	if !c.seen && n > 0 {
		c.buf = append(c.buf, p[:n]...)
		if i := strings.IndexByte(string(c.buf), '\n'); i >= 0 || len(c.buf) > 255 {
			if i < 0 {
				i = len(c.buf)
			}
			c.banner = strings.TrimRight(string(c.buf[:i]), "\r")
			c.seen = true
		}
	}
	c.mu.Unlock()
	return n, err
}

// sshOnce does one key exchange offering only algo and returns the host key.
// It stops right after the server proves its host key: no user name is sent
// and no authentication is attempted.
func sshOnce(ctx context.Context, dial DialFunc, addr, algo string) (ssh.PublicKey, string, error) {
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	bc := &bannerConn{Conn: raw, r: bufio.NewReader(raw)}
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:              "nymvantage",
		HostKeyAlgorithms: []string{algo},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errGotKey
		},
	}
	_, _, _, err = ssh.NewClientConn(bc, addr, cfg)
	bc.mu.Lock()
	banner := bc.banner
	bc.mu.Unlock()
	if got != nil {
		return got, banner, nil
	}
	if err == nil {
		err = errors.New("handshake ended without a host key")
	}
	return nil, banner, err
}

// KeyType is the key type a host key algorithm asks for (rsa-sha2-512 asks
// for an ssh-rsa key).
func KeyType(algo string) string {
	switch algo {
	case ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA:
		return ssh.KeyAlgoRSA
	}
	return algo
}

// IsNoSuchKey reports a server that simply has no key of the asked type.
func IsNoSuchKey(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no common algorithm for host key")
}

// SSH asks the server at host:port for its host key once per algorithm,
// through dial, and records each key. Algorithms the server does not have are
// left out; other failures are listed in Errors. The algorithms run one after
// another, so a single vantage point never opens a burst of connections.
func SSH(ctx context.Context, dial DialFunc, host string, port int, algos []string) (*SSHView, error) {
	t0 := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	v := &SSHView{Keys: map[string]*SSHKey{}, Errors: map[string]string{}}
	var lastErr error
	for _, algo := range algos {
		if err := ctx.Err(); err != nil {
			lastErr = err
			v.Errors[KeyType(algo)] = err.Error() // not asked: no answer, never "absent"
			continue
		}
		key, banner, err := sshOnce(ctx, dial, addr, algo)
		if banner != "" && v.Banner == "" {
			v.Banner = banner
		}
		switch {
		case err == nil:
			k := &SSHKey{
				Type:        key.Type(),
				Fingerprint: ssh.FingerprintSHA256(key),
				Authorized:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
				Key:         key,
			}
			v.Keys[k.Type] = k
		case IsNoSuchKey(err):
		default:
			lastErr = err
			v.Errors[KeyType(algo)] = err.Error()
		}
	}
	v.Took = time.Since(t0).Seconds()
	if len(v.Keys) == 0 {
		if lastErr == nil {
			lastErr = errors.New("server offered none of the asked host key types")
		}
		return v, lastErr
	}
	return v, nil
}
