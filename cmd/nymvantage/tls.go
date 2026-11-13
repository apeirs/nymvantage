package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sync"

	"github.com/apeirs/nymvantage/probe"
	"github.com/apeirs/nymvantage/vantage"
	"github.com/apeirs/nymvantage/verdict"
)

// answer is one vantage point's result.
type answer[T any] struct {
	V    *vantage.Vantage
	View T
	Err  error
}

// each runs fn from every usable vantage in set (and local, if not nil) at
// the same time. Vantages that could not be set up carry their setup error.
func each[T any](ctx context.Context, set vantage.Set, local *vantage.Vantage, fn func(context.Context, probe.DialFunc) (T, error)) ([]answer[T], *answer[T]) {
	out := make([]answer[T], len(set))
	var loc *answer[T]
	var wg sync.WaitGroup
	for i, v := range set {
		out[i].V = v
		if v.Err != nil {
			out[i].Err = fmt.Errorf("no Nym client: %w", v.Err)
			continue
		}
		wg.Add(1)
		go func(i int, v *vantage.Vantage) {
			defer wg.Done()
			out[i].View, out[i].Err = fn(ctx, probe.DialFunc(v.Dial))
		}(i, v)
	}
	if local != nil {
		loc = &answer[T]{V: local}
		wg.Add(1)
		go func() {
			defer wg.Done()
			loc.View, loc.Err = fn(ctx, probe.DialFunc(local.Dial))
		}()
	}
	wg.Wait()
	return out, loc
}

type tlsReport struct {
	Target string          `json:"target"`
	SNI    string          `json:"sni"`
	Views  []tlsViewReport `json:"views"`
	Local  *tlsViewReport  `json:"local,omitempty"`
	Result verdict.Result  `json:"result"`
	Level  string          `json:"compared"`
	Note   string          `json:"note,omitempty"`
}

type tlsViewReport struct {
	Vantage string         `json:"vantage"`
	Via     string         `json:"via"`
	View    *probe.TLSView `json:"view,omitempty"`
	Error   string         `json:"error,omitempty"`
}

func runTLS(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runTLSWith(ctx, args, stdout, stderr, nil)
}

func runTLSWith(ctx context.Context, args []string, stdout, stderr io.Writer, c *common) int {
	fs := flag.NewFlagSet("tls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if c == nil {
		c = &common{}
	}
	c.register(fs)
	sni := fs.String("sni", "", "server name to send and verify (default: the host)")
	c.registerProbeTimeout(fs)
	strict := fs.Bool("strict", false, "treat different certificates from the same CA as a difference (by default they are normal: CDNs and load balancers rotate certificates)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: nymvantage tls [options] HOST[:PORT]\n\nCompare the TLS certificate HOST presents to several Nym vantage points (and to you, with --local).\n\nOptions:")
		fs.PrintDefaults()
	}
	if err := parseInterspersed(fs, args); err != nil || fs.NArg() != 1 {
		if err == nil {
			fs.Usage()
		}
		return 3
	}
	host, port, err := splitHostPort(fs.Arg(0), 443)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	name := *sni
	if name == "" {
		name = host
	}
	roots, err := c.roots()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	set, local, err := c.vantages(ctx, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	defer set.Close()
	if !c.jsonOut {
		header(stdout, fmt.Sprintf("tls %s:%d (SNI %s)", host, port, name), c, set)
	}
	mix, loc := each(ctx, set, local, func(ctx context.Context, d probe.DialFunc) (*probe.TLSView, error) {
		ctx, cancel := context.WithTimeout(ctx, c.probeTO)
		defer cancel()
		return probe.TLS(ctx, d, host, port, name, roots)
	})
	set.Close() // stop the Nym clients as soon as the answers are in

	rep := tlsReport{Target: fmt.Sprintf("%s:%d", host, port), SNI: name, Level: "certificate"}
	certObs, issuerObs := make([]verdict.Obs, len(mix)), make([]verdict.Obs, len(mix))
	allTrusted := true
	for i, a := range mix {
		rv := tlsViewReport{Vantage: a.V.Name, Via: a.V.Label, View: a.View, Error: errText(a.Err)}
		rep.Views = append(rep.Views, rv)
		certObs[i] = verdict.Obs{Vantage: a.V.Name, Err: a.Err}
		issuerObs[i] = verdict.Obs{Vantage: a.V.Name, Err: a.Err}
		if a.Err == nil {
			certObs[i].Key = a.View.LeafSHA256
			issuerObs[i].Key = a.View.IssuerID()
			allTrusted = allTrusted && a.View.Trusted
		}
	}
	var certRef, issuerRef *verdict.Ref
	if loc != nil {
		rep.Local = &tlsViewReport{Vantage: "local", Via: loc.V.Label, View: loc.View, Error: errText(loc.Err)}
		certRef = &verdict.Ref{Name: "your direct connection", Err: loc.Err}
		issuerRef = &verdict.Ref{Name: "your direct connection", Err: loc.Err}
		if loc.Err == nil {
			certRef.Key = loc.View.LeafSHA256
			issuerRef.Key = loc.View.IssuerID()
			allTrusted = allTrusted && loc.View.Trusted
		}
	}
	res := verdict.Decide(certObs, c.quorumOr(), certRef)
	if (res.Code == verdict.Split || res.Code == verdict.Mismatch) && !*strict {
		ires := verdict.Decide(issuerObs, c.quorumOr(), issuerRef)
		if ires.Code.Exit() == 0 && allTrusted {
			rep.Level = "issuing CA"
			rep.Note = "the certificates differ, but all come from the same CA key and are publicly trusted: normal for CDNs and load balancers (use --strict to count this as a difference)"
			res = ires
		} else if ires.Code.Exit() == 1 {
			rep.Note = "not only the certificate but the CA that issued it differs"
		}
	}
	if res.Code.Exit() == 0 && rep.Level == "certificate" {
		for _, a := range mix {
			if a.Err == nil && !a.View.Trusted {
				rep.Note = "every vantage point sees this same certificate and it does not verify: a problem of the server itself (expired, wrong name or unknown CA), not interception on your path"
				break
			}
		}
	}
	rep.Result = res
	if c.jsonOut {
		writeJSON(stdout, rep)
		return res.Code.Exit()
	}
	for _, v := range append(rep.Views, derefTLS(rep.Local)...) {
		printTLSView(stdout, v)
	}
	fmt.Fprintf(stdout, "verdict: %s (compared by %s): %s\n", res.Code, rep.Level, res.Reason)
	if rep.Note != "" {
		fmt.Fprintf(stdout, "  note: %s\n", rep.Note)
	}
	return res.Code.Exit()
}

func derefTLS(v *tlsViewReport) []tlsViewReport {
	if v == nil {
		return nil
	}
	return []tlsViewReport{*v}
}

func printTLSView(w io.Writer, r tlsViewReport) {
	fmt.Fprintf(w, "  %-8s %-26s ", r.Vantage, r.Via)
	if r.View == nil {
		fmt.Fprintf(w, "no answer: %s\n", r.Error)
		return
	}
	v := r.View
	trust := "trusted"
	if !v.Trusted {
		trust = "NOT TRUSTED (" + errText(fmt.Errorf("%s", v.TrustError)) + ")"
	}
	fmt.Fprintf(w, "cert %s  key %s  issuer %q  until %s  %s  [%.1fs]\n",
		probe.ShortHex(v.LeafSHA256), probe.ShortHex(v.SPKISHA256), probe.ShortDN(v.Issuer), v.NotAfter.Format("2006-01-02"), trust, v.Took)
}
