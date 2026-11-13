// Package probe looks at a server from one vantage point: its TLS
// certificate, its SSH host keys, or the bytes behind a URL.
package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// DialFunc opens a TCP stream to "host:port".
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// TLSView is what one vantage point was shown by a TLS server.
type TLSView struct {
	LeafSHA256  string    `json:"leaf_sha256"`   // SHA-256 of the leaf certificate (DER)
	SPKISHA256  string    `json:"spki_sha256"`   // SHA-256 of the leaf's public key (as for HPKP pins)
	IssuerKeyID string    `json:"issuer_key_id"` // Authority Key Identifier of the leaf (who signed it)
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	ChainLen    int       `json:"chain_len"`
	Trusted     bool      `json:"trusted"`               // chain verifies for the name against the system roots
	TrustError  string    `json:"trust_error,omitempty"` // why not
	TLSVersion  string    `json:"tls_version"`
	Took        float64   `json:"seconds"`
}

// IssuerID identifies the CA key that signed the leaf: the AKI when present,
// else the issuer's DN.
func (v *TLSView) IssuerID() string {
	if v.IssuerKeyID != "" {
		return "aki:" + v.IssuerKeyID
	}
	return "dn:" + v.Issuer
}

// TLS connects to host:port through dial, completes a TLS handshake with SNI
// name, and records the certificate chain the server presented. It accepts
// any certificate so it can report what it saw, then verifies the chain
// against roots (nil = system roots) itself. No application data is sent.
func TLS(ctx context.Context, dial DialFunc, host string, port int, name string, roots *x509.CertPool) (*TLSView, error) {
	t0 := time.Now()
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         name,
		InsecureSkipVerify: true, // verified below, after recording what was presented
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	st := conn.ConnectionState()
	_ = conn.Close()
	if len(st.PeerCertificates) == 0 {
		return nil, fmt.Errorf("server sent no certificate")
	}
	leaf := st.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	v := &TLSView{
		LeafSHA256:  hex.EncodeToString(sum[:]),
		SPKISHA256:  hex.EncodeToString(spki[:]),
		IssuerKeyID: hex.EncodeToString(leaf.AuthorityKeyId),
		Issuer:      leaf.Issuer.String(),
		Subject:     leaf.Subject.String(),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		ChainLen:    len(st.PeerCertificates),
		TLSVersion:  tls.VersionName(st.Version),
	}
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: inter})
	v.Trusted = verr == nil
	if verr != nil {
		v.TrustError = verr.Error()
	}
	v.Took = time.Since(t0).Seconds()
	return v, nil
}

// ShortHex shortens a hex digest for display: first 16 characters.
func ShortHex(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

// ShortDN returns the CN (or O) of an RDN string for display.
func ShortDN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		if v, ok := strings.CutPrefix(part, "CN="); ok {
			return v
		}
	}
	for _, part := range strings.Split(dn, ",") {
		if v, ok := strings.CutPrefix(part, "O="); ok {
			return v
		}
	}
	return dn
}
