package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/apeirs/nymvantage/probe"
	"github.com/apeirs/nymvantage/verdict"
)

type sshReport struct {
	Target     string                    `json:"target"`
	Views      []sshViewReport           `json:"views"`
	Local      *sshViewReport            `json:"local,omitempty"`
	Types      map[string]sshTypeVerdict `json:"types"`
	Verdict    verdict.Code              `json:"verdict"`
	KnownHosts string                    `json:"known_hosts_file,omitempty"`
	Lines      []string                  `json:"known_hosts_lines,omitempty"`
	Added      int                       `json:"added,omitempty"`
	Reason     string                    `json:"reason,omitempty"`
}

type sshViewReport struct {
	Vantage string         `json:"vantage"`
	Via     string         `json:"via"`
	View    *probe.SSHView `json:"view,omitempty"`
	Error   string         `json:"error,omitempty"`
}

type sshTypeVerdict struct {
	Fingerprint string          `json:"fingerprint,omitempty"`
	Network     verdict.Result  `json:"mixnet"`
	KnownHosts  *verdict.Result `json:"known_hosts,omitempty"`
	Local       *verdict.Result `json:"local,omitempty"`
	Code        verdict.Code    `json:"verdict"`
}

const absent = "(no key of this type)"

func defaultKnownHosts() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

func runSSH(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runSSHWith(ctx, args, stdout, stderr, nil)
}

func runSSHWith(ctx context.Context, args []string, stdout, stderr io.Writer, c *common) int {
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if c == nil {
		c = &common{}
	}
	c.register(fs)
	khFile := fs.String("known-hosts", defaultKnownHosts(), "known_hosts file to check the keys against (\"\" to skip)")
	add := fs.Bool("add", false, "append the keys to --known-hosts, only if every vantage point agreed and the file has no other key of that type for the host")
	hash := fs.Bool("hash", false, "with --add, hash the host name in the new lines (like HashKnownHosts yes)")
	c.registerProbeTimeout(fs)
	allTypes := fs.Bool("all-types", false, "also ask for ecdsa-sha2-nistp384 and -nistp521 keys (two more handshakes per vantage point)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: nymvantage ssh [options] HOST[:PORT]\n\nAsk HOST for its SSH host keys from several Nym vantage points (no login is attempted), compare them,\nand check them against your known_hosts. Use it before you trust a new server's key.\n\nOptions:")
		fs.PrintDefaults()
	}
	if err := parseInterspersed(fs, args); err != nil || fs.NArg() != 1 {
		if err == nil {
			fs.Usage()
		}
		return 3
	}
	host, port, err := splitHostPort(fs.Arg(0), 22)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	algos := probe.DefaultSSHAlgos
	if *allTypes {
		algos = probe.AllSSHAlgos
	}
	var kh ssh.HostKeyCallback
	if *khFile != "" {
		if _, err := os.Stat(*khFile); err == nil {
			kh, err = knownhosts.New(*khFile)
			if err != nil {
				fmt.Fprintln(stderr, "error: reading known_hosts:", err)
				return 3
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stderr, "error:", err)
			return 3
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	set, local, err := c.vantages(ctx, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	defer set.Close()
	target := net.JoinHostPort(host, fmt.Sprint(port))
	if !c.jsonOut {
		header(stdout, "ssh "+target, c, set)
	}
	mix, loc := each(ctx, set, local, func(ctx context.Context, d probe.DialFunc) (*probe.SSHView, error) {
		ctx, cancel := context.WithTimeout(ctx, c.probeTO)
		defer cancel()
		return probe.SSH(ctx, d, host, port, algos)
	})
	set.Close()

	rep := sshReport{Target: target, Types: map[string]sshTypeVerdict{}, KnownHosts: *khFile}
	types := map[string]bool{}
	for _, a := range mix {
		rep.Views = append(rep.Views, sshViewReport{Vantage: a.V.Name, Via: a.V.Label, View: a.View, Error: errText(a.Err)})
		if a.Err == nil {
			for t := range a.View.Keys {
				types[t] = true
			}
		}
	}
	if loc != nil {
		rep.Local = &sshViewReport{Vantage: "local", Via: loc.V.Label, View: loc.View, Error: errText(loc.Err)}
		if loc.Err == nil {
			for t := range loc.View.Keys {
				types[t] = true
			}
		}
	}
	// keyOf is what a view says about key type t: its fingerprint, "absent"
	// when the server said it has no such key, or an error when asking failed
	// (that vantage gave no answer for t; a failure is never "absent").
	keyOf := func(v *probe.SSHView, t string) (string, error) {
		if k, ok := v.Keys[t]; ok {
			return k.Fingerprint, nil
		}
		if e, ok := v.Errors[t]; ok {
			return "", errors.New(e)
		}
		return absent, nil
	}
	var codes []verdict.Code
	var sorted []string
	for t := range types {
		sorted = append(sorted, t)
	}
	sort.Strings(sorted)
	agreedKeys := map[string]ssh.PublicKey{}
	for _, t := range sorted {
		obs := make([]verdict.Obs, len(mix))
		for i, a := range mix {
			obs[i] = verdict.Obs{Vantage: a.V.Name, Err: a.Err}
			if a.Err == nil {
				obs[i].Key, obs[i].Err = keyOf(a.View, t)
			}
		}
		tv := sshTypeVerdict{Network: verdict.Decide(obs, c.quorumOr(), nil)}
		var refs []verdict.Code // comparisons with known_hosts and --local
		if tv.Network.Code == verdict.Agree {
			tv.Fingerprint = tv.Network.Agreed
			for _, a := range mix {
				if a.Err == nil {
					if k, ok := a.View.Keys[t]; ok {
						agreedKeys[t] = k.Key
					}
					break
				}
			}
		}
		if kh != nil && tv.Network.Code == verdict.Agree {
			if ref := knownHostsRef(kh, target, port, t, agreedKeys[t]); ref != nil {
				r := verdict.Decide(obs, c.quorumOr(), ref)
				tv.KnownHosts = &r
				refs = append(refs, r.Code)
			}
		}
		if loc != nil {
			ref := &verdict.Ref{Name: "your direct connection", Err: loc.Err}
			if loc.Err == nil {
				ref.Key, ref.Err = keyOf(loc.View, t)
			}
			r := verdict.Decide(obs, c.quorumOr(), ref)
			tv.Local = &r
			refs = append(refs, r.Code)
		}
		// A comparison with a reference includes the network's own verdict
		// (a split stays a split), so with references it replaces it.
		tv.Code = tv.Network.Code
		if len(refs) > 0 {
			tv.Code = verdict.Worst(refs...)
		}
		rep.Types[t] = tv
		codes = append(codes, tv.Code)
	}
	if len(codes) == 0 {
		// No vantage point got any key: say why, never "fine".
		obs := make([]verdict.Obs, len(mix))
		for i, a := range mix {
			obs[i] = verdict.Obs{Vantage: a.V.Name, Err: a.Err}
		}
		r := verdict.Decide(obs, c.quorumOr(), nil)
		rep.Reason = r.Reason
		codes = append(codes, r.Code)
	}
	rep.Verdict = verdict.Worst(codes...)

	// known_hosts lines for keys every vantage agreed on, and not yet known.
	if rep.Verdict.Exit() == 0 {
		for _, t := range sorted {
			k := agreedKeys[t]
			if k == nil || k.Type() == "" {
				continue
			}
			if tv := rep.Types[t]; tv.KnownHosts != nil {
				continue // already in known_hosts (and matching, or the verdict would not be clean)
			}
			name := knownhosts.Normalize(target)
			if *hash {
				name = knownhosts.HashHostname(name)
			}
			rep.Lines = append(rep.Lines, knownhosts.Line([]string{name}, k))
		}
		if *add && len(rep.Lines) > 0 {
			if err := appendLines(*khFile, rep.Lines); err != nil {
				fmt.Fprintln(stderr, "error: --add:", err)
				return 2
			}
			rep.Added = len(rep.Lines)
		}
	}
	refused := func() {
		if *add && rep.Verdict.Exit() != 0 {
			fmt.Fprintln(stderr, "--add: nothing written, the verdict is not clean")
		}
	}

	if c.jsonOut {
		writeJSON(stdout, rep)
		refused()
		return rep.Verdict.Exit()
	}
	for _, v := range append(rep.Views, derefSSH(rep.Local)...) {
		printSSHView(stdout, v, sorted)
	}
	for _, t := range sorted {
		tv := rep.Types[t]
		line := fmt.Sprintf("  %-20s %s: %s", t, tv.Network.Code, tv.Network.Reason)
		if tv.Fingerprint != "" {
			line = fmt.Sprintf("  %-20s %s %s: %s", t, tv.Network.Code, tv.Fingerprint, tv.Network.Reason)
		}
		fmt.Fprintln(stdout, line)
		if tv.KnownHosts != nil {
			fmt.Fprintf(stdout, "  %-20s known_hosts %s: %s\n", "", tv.KnownHosts.Code, tv.KnownHosts.Reason)
		}
		if tv.Local != nil {
			fmt.Fprintf(stdout, "  %-20s local %s: %s\n", "", tv.Local.Code, tv.Local.Reason)
		}
	}
	if rep.Reason != "" {
		fmt.Fprintf(stdout, "verdict: %s: %s\n", rep.Verdict, rep.Reason)
	} else {
		fmt.Fprintf(stdout, "verdict: %s\n", rep.Verdict)
	}
	if len(rep.Lines) > 0 {
		if rep.Added > 0 {
			fmt.Fprintf(stdout, "added %d line(s) to %s\n", rep.Added, *khFile)
		} else {
			fmt.Fprintln(stdout, "known_hosts lines (not in your known_hosts yet; --add appends them):")
			for _, l := range rep.Lines {
				fmt.Fprintln(stdout, "  "+l)
			}
		}
	}
	refused()
	return rep.Verdict.Exit()
}

// knownHostsRef returns what known_hosts says about key type t for target,
// or nil when it has no key of that type for the host. When the stored key of
// that type is a different one, the reference holds its fingerprint, so the
// comparison reports MISMATCH.
func knownHostsRef(kh ssh.HostKeyCallback, target string, port int, t string, agreed ssh.PublicKey) *verdict.Ref {
	if agreed == nil {
		return nil
	}
	remote := &net.TCPAddr{IP: net.IPv4zero, Port: port}
	err := kh(target, remote, agreed)
	if err == nil {
		return &verdict.Ref{Name: "your known_hosts", Key: ssh.FingerprintSHA256(agreed)}
	}
	var re *knownhosts.RevokedError
	if errors.As(err, &re) {
		return &verdict.Ref{Name: "your known_hosts (this key is marked @revoked)", Key: "revoked:" + ssh.FingerprintSHA256(agreed)}
	}
	var ke *knownhosts.KeyError
	if errors.As(err, &ke) {
		for _, w := range ke.Want {
			if w.Key.Type() == t {
				return &verdict.Ref{Name: fmt.Sprintf("your known_hosts (%s:%d)", w.Filename, w.Line), Key: ssh.FingerprintSHA256(w.Key)}
			}
		}
	}
	return nil
}

func appendLines(file string, lines []string) error {
	if file == "" {
		return errors.New("no --known-hosts file")
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func derefSSH(v *sshViewReport) []sshViewReport {
	if v == nil {
		return nil
	}
	return []sshViewReport{*v}
}

func printSSHView(w io.Writer, r sshViewReport, types []string) {
	fmt.Fprintf(w, "  %-8s %-26s ", r.Vantage, r.Via)
	if r.View == nil || len(r.View.Keys) == 0 {
		fmt.Fprintf(w, "no answer: %s\n", r.Error)
		return
	}
	var parts []string
	for _, t := range types {
		if k, ok := r.View.Keys[t]; ok {
			short := strings.TrimPrefix(t, "ecdsa-sha2-")
			short = strings.TrimPrefix(short, "ssh-")
			parts = append(parts, fmt.Sprintf("%s %s", short, trimFP(k.Fingerprint)))
		}
	}
	fmt.Fprintf(w, "%s  %q [%.1fs]\n", strings.Join(parts, "  "), r.View.Banner, r.View.Took)
}

func trimFP(fp string) string {
	if len(fp) > 7+16 {
		return fp[:7+16] + "…"
	}
	return fp
}
