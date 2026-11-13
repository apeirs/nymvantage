package fakes

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

// HostKeys generates SSH host signers: "ed25519", "ecdsa" (P-256), "rsa".
func HostKeys(kinds ...string) []ssh.Signer {
	var out []ssh.Signer
	for _, k := range kinds {
		var key any
		switch k {
		case "ed25519":
			_, key, _ = ed25519.GenerateKey(rand.Reader)
		case "ecdsa":
			key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "rsa":
			key, _ = rsa.GenerateKey(rand.Reader, 2048)
		default:
			panic("unknown key kind " + k)
		}
		s, err := ssh.NewSignerFromKey(key)
		if err != nil {
			panic(err)
		}
		out = append(out, s)
	}
	return out
}

// SSHServer is a test SSH server. It counts connections and authentication
// attempts (a host key check must never get as far as authentication).
type SSHServer struct {
	Addr      string
	Conns     Counter
	AuthTries atomic.Int64
	ln        net.Listener
}

// NewSSHServer serves the given host keys on 127.0.0.1:0.
func NewSSHServer(keys []ssh.Signer) *SSHServer {
	s := &SSHServer{}
	s.ln = Listen(&s.Conns)
	s.Addr = s.ln.Addr().String()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			s.AuthTries.Add(1)
			return nil, errDenied
		},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			s.AuthTries.Add(1)
			return nil, errDenied
		},
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			s.AuthTries.Add(1)
			return nil, errDenied
		},
		// Count the "none" method too: any user-auth request at all is a login attempt.
		NoClientAuth: true,
		NoClientAuthCallback: func(ssh.ConnMetadata) (*ssh.Permissions, error) {
			s.AuthTries.Add(1)
			return nil, errDenied
		},
		ServerVersion: "SSH-2.0-FakeSSH_1.0",
	}
	for _, k := range keys {
		cfg.AddHostKey(k)
	}
	go func() {
		for {
			c, err := s.ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(ssh.Prohibited, "no")
				}
			}()
		}
	}()
	return s
}

func (s *SSHServer) Close() { s.ln.Close() }

type denied struct{}

func (denied) Error() string { return "denied" }

var errDenied = denied{}
