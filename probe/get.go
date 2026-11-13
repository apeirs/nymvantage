package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// GetView is what one vantage point received for a URL.
type GetView struct {
	Status      int     `json:"status"`
	SHA256      string  `json:"sha256"`
	Size        int64   `json:"size"`
	ContentType string  `json:"content_type,omitempty"`
	FinalURL    string  `json:"final_url"`
	Took        float64 `json:"seconds"`
	File        string  `json:"-"` // temporary copy of the body (caller removes it)
}

// ErrTooLarge means the body exceeded the size limit.
var ErrTooLarge = errors.New("response larger than --max-size")

// Get fetches rawURL through dial and hashes the body while it streams into a
// temporary file in dir. https only, also on redirects; TLS is verified
// against roots (nil = system roots); no User-Agent, no cookies, no proxy from
// the environment, and no dialer other than dial.
func Get(ctx context.Context, dial DialFunc, rawURL string, maxSize int64, roots *x509.CertPool, dir string) (*GetView, error) {
	t0 := time.Now()
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("only https:// URLs are fetched (got %q)", u.Scheme)
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         dial,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 60 * time.Second,
		DisableKeepAlives:   true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-https %s", req.URL.Redacted())
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "")
	req.Header.Set("Accept", "*/*")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	f, err := os.CreateTemp(dir, "nymvantage-get-")
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if n > maxSize {
		return nil, fmt.Errorf("%w (%d bytes)", ErrTooLarge, maxSize)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	ok = true
	return &GetView{
		Status:      resp.StatusCode,
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		Size:        n,
		ContentType: resp.Header.Get("Content-Type"),
		FinalURL:    resp.Request.URL.String(),
		Took:        time.Since(t0).Seconds(),
		File:        f.Name(),
	}, nil
}
