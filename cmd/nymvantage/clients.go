package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/apeirs/nymvantage/nym"
)

// runClients starts N throwaway Nym clients on different exits and keeps them
// running until interrupted, so several checks can share them (--proxy).
func runClients(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runClientsWith(ctx, args, stdout, stderr, nil)
}

func runClientsWith(ctx context.Context, args []string, stdout, stderr io.Writer, c *common) int {
	fs := flag.NewFlagSet("clients", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if c == nil {
		c = &common{}
	}
	fs.IntVar(&c.n, "n", 3, "number of Nym clients (each a new identity and a different exit gateway)")
	fs.StringVar(&c.binary, "binary", "", "path to nym-socks5-client (default: $NYMVANTAGE_NYM_SOCKS5, then $PATH)")
	fs.StringVar(&c.api, "nym-api", nym.NymAPI, "nym-api URL to list exit gateways from")
	fs.Float64Var(&c.minPerf, "min-performance", 0.95, "skip exit gateways below this nym-api performance score")
	fs.StringVar(&c.tmp, "tmpdir", "", "where the throwaway identities live while they run (default: $TMPDIR)")
	fs.BoolVar(&c.verbose, "v", false, "print each step on stderr")
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: nymvantage clients [options]

Start N throwaway Nym clients, each on a different exit gateway, print their
SOCKS5 addresses and keep them running until Ctrl-C (then they are stopped and
their identities deleted). Pass the printed --proxy flags to tls/ssh/get to run
many checks without starting new clients each time.

Trade-off: checks that share these clients share their exits, so an exit can
link those checks to each other (not to you). For one-off checks, let each
command start its own clients (the default).

Options:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			fs.Usage()
		}
		return 3
	}
	sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	set, _, err := c.vantages(sctx, stderr)
	cancel()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	defer set.Close()
	var flags []string
	for _, v := range set {
		if v.Err != nil {
			fmt.Fprintf(stdout, "  %-6s no client: %s\n", v.Name, errText(v.Err))
			continue
		}
		fmt.Fprintf(stdout, "  %-6s %-21s %s, ready in %.1fs\n", v.Name, v.Proxy, v.Label, v.Ready.Seconds())
		flags = append(flags, "--proxy "+v.Proxy)
	}
	if len(flags) == 0 {
		fmt.Fprintln(stderr, "error: no Nym client started")
		return 2
	}
	fmt.Fprintf(stdout, "%d Nym client(s) running; Ctrl-C stops them and deletes their identities. Use them with:\n%s\n", len(flags), strings.Join(flags, " "))
	<-ctx.Done()
	return 0
}
