// Command nymvantage checks whether you see the same TLS certificate, SSH host
// key or file as the rest of the world, by looking at the server from several
// independent points on the Nym mixnet: a new, throwaway Nym client and a
// different exit gateway for each.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/apeirs/nymvantage/mixnet"
	"github.com/apeirs/nymvantage/nym"
	"github.com/apeirs/nymvantage/vantage"
)

var version = "0.1.0"

const usage = `nymvantage: see what the rest of the world sees, through the Nym mixnet.

Usage:
  nymvantage tls HOST[:PORT]        compare the TLS certificate (default port 443)
  nymvantage ssh HOST[:PORT]        compare SSH host keys, check them against known_hosts (port 22)
  nymvantage get URL                download a file only if every vantage point got the same bytes
  nymvantage clients [-n N]         keep N throwaway Nym clients running for many checks (--proxy)
  nymvantage exits                  list the Nym exit gateways vantage points are picked from
  nymvantage version

Each check starts N new Nym clients (default 3), each with a new mixnet
identity and a different exit gateway, in different countries where possible,
and asks the server through all of them at once. The server sees N unrelated
Nym users; no exit sees more than one of the checks. Nothing is sent outside
the mixnet unless you add --local, which also asks over your own connection
and compares it with the mixnet's answer.

Exit status: 0 the views agree (and match yours), 1 a difference was seen,
2 not enough vantage points answered (never treated as "fine"), 3 usage error.

Run "nymvantage CMD -h" for the options of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(3)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var code int
	switch os.Args[1] {
	case "tls":
		code = runTLS(ctx, os.Args[2:], os.Stdout, os.Stderr)
	case "ssh":
		code = runSSH(ctx, os.Args[2:], os.Stdout, os.Stderr)
	case "get":
		code = runGet(ctx, os.Args[2:], os.Stdout, os.Stderr)
	case "clients":
		code = runClients(ctx, os.Args[2:], os.Stdout, os.Stderr)
	case "exits":
		code = runExits(os.Args[2:], os.Stdout, os.Stderr)
	case "version", "--version", "-version":
		fmt.Println("nymvantage", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		code = 3
	}
	os.Exit(code)
}

// common holds the options every check takes.
type common struct {
	n        int
	quorum   int
	local    bool
	proxies  multiFlag
	binary   string
	api      string
	minPerf  float64
	timeout  time.Duration
	jsonOut  bool
	verbose  bool
	tmp      string
	rootsPEM string
	probeTO  time.Duration

	// for tests: replaces nym-socks5-client and the nym-api
	starter   vantage.Starter
	providers []nym.ExitProvider
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func (c *common) register(fs *flag.FlagSet) {
	fs.IntVar(&c.n, "n", 3, "number of mixnet vantage points (new Nym client + exit each)")
	fs.IntVar(&c.quorum, "quorum", 0, "mixnet answers needed for a verdict (default: 2, or N if N < 2)")
	fs.BoolVar(&c.local, "local", false, "also ask over your own direct connection and compare it (the only non-mixnet traffic nymvantage ever sends)")
	fs.Var(&c.proxies, "proxy", "use a Nym SOCKS5 client you run (host:port) as a vantage point instead of starting clients; repeat for more")
	fs.StringVar(&c.binary, "binary", "", "path to nym-socks5-client (default: $NYMVANTAGE_NYM_SOCKS5, then $PATH)")
	fs.StringVar(&c.api, "nym-api", nym.NymAPI, "nym-api URL to list exit gateways from")
	fs.Float64Var(&c.minPerf, "min-performance", 0.95, "skip exit gateways below this nym-api performance score")
	fs.DurationVar(&c.timeout, "timeout", 3*time.Minute, "give up on the whole check after this long")
	fs.BoolVar(&c.jsonOut, "json", false, "print the result as JSON")
	fs.BoolVar(&c.verbose, "v", false, "print each mixnet step on stderr")
	fs.StringVar(&c.tmp, "tmpdir", "", "where throwaway Nym client identities live while they run (default: $TMPDIR)")
	fs.StringVar(&c.rootsPEM, "ca-file", "", "trust these PEM roots instead of the system's (for tests and private CAs)")
}

func (c *common) quorumOr() int {
	if c.quorum > 0 {
		return c.quorum
	}
	n := c.n
	if len(c.proxies) > 0 {
		n = len(c.proxies)
	}
	return min(2, n)
}

func (c *common) roots() (*x509.CertPool, error) {
	if c.rootsPEM == "" {
		return nil, nil
	}
	b, err := os.ReadFile(c.rootsPEM)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no PEM certificates", c.rootsPEM)
	}
	return p, nil
}

// registerProbeTimeout adds --probe-timeout (tls and ssh; a download takes as
// long as it takes, within --timeout).
func (c *common) registerProbeTimeout(fs *flag.FlagSet) {
	fs.DurationVar(&c.probeTO, "probe-timeout", 45*time.Second, "give up on one vantage point after this long (it then counts as not answering)")
}

// vantages sets up the mixnet vantage points (and the local one if asked).
// The caller must Close the set.
func (c *common) vantages(ctx context.Context, stderr io.Writer) (vantage.Set, *vantage.Vantage, error) {
	var trace mixnet.Tracer
	if c.verbose {
		trace = func(format string, args ...any) { fmt.Fprintf(stderr, "  · "+format+"\n", args...) }
	}
	var set vantage.Set
	if len(c.proxies) > 0 {
		s, err := vantage.FromProxies(c.proxies, trace)
		if err != nil {
			return nil, nil, err
		}
		set = s
	} else {
		if c.n < 1 {
			return nil, nil, errors.New("-n must be at least 1")
		}
		start := c.starter
		if start == nil {
			bin, err := nym.FindBinary(c.binary)
			if err != nil {
				return nil, nil, err
			}
			start = vantage.EphemeralStarter(bin, c.tmp)
		}
		ps := c.providers
		if ps == nil {
			var err error
			ps, err = nym.ListExitProviders(c.api, c.minPerf)
			if err != nil {
				return nil, nil, fmt.Errorf("listing Nym exit gateways: %w", err)
			}
		}
		s, err := vantage.Ephemeral(ctx, ps, c.n, 2, start, trace)
		if err != nil {
			return nil, nil, err
		}
		set = s
		for _, v := range set {
			if c.verbose && v.Err == nil {
				fmt.Fprintf(stderr, "  · %s: new Nym client via %s ready in %.1fs\n", v.Name, v.Label, v.Ready.Seconds())
			}
		}
	}
	var local *vantage.Vantage
	if c.local {
		local = vantage.Local()
	}
	return set, local, nil
}

// splitHostPort accepts "host", "host:port" and "[v6]:port".
func splitHostPort(s string, def int) (string, int, error) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("bad port in %q", s)
		}
		return h, port, nil
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if s == "" || strings.ContainsAny(s, "/ ") {
		return "", 0, fmt.Errorf("bad host %q", s)
	}
	return s, def, nil
}

func header(w io.Writer, what string, c *common, set vantage.Set) {
	if len(c.proxies) > 0 {
		fmt.Fprintf(w, "%s: %d vantage point(s) through Nym clients you run (nymvantage cannot check that they use different exits)", what, len(set))
	} else {
		fmt.Fprintf(w, "%s: %d vantage points through the Nym mixnet, each a new Nym client and a different exit gateway", what, len(set))
	}
	if c.local {
		fmt.Fprint(w, ", plus your direct connection")
	}
	fmt.Fprintln(w)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func runExits(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("exits", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.String("nym-api", nym.NymAPI, "nym-api URL")
	minPerf := fs.Float64("min-performance", 0.95, "skip exit gateways below this performance score")
	jsonOut := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	ps, err := nym.ListExitProviders(*api, *minPerf)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *jsonOut {
		writeJSON(stdout, ps)
		return 0
	}
	countries := map[string]int{}
	for _, p := range ps {
		countries[p.Country]++
	}
	fmt.Fprintf(stdout, "%d exit gateways with a network requester and performance >= %.2f, in %d countries\n", len(ps), *minPerf, len(countries))
	for _, p := range ps {
		fmt.Fprintf(stdout, "  node %-5d %-3s perf %.2f  %s\n", p.NodeID, p.Country, p.Performance, p.Version)
	}
	return 0
}
