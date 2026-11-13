package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apeirs/nymvantage/probe"
	"github.com/apeirs/nymvantage/verdict"
)

type getReport struct {
	URL    string          `json:"url"`
	Views  []getViewReport `json:"views"`
	Local  *getViewReport  `json:"local,omitempty"`
	Expect string          `json:"expect,omitempty"`
	Result verdict.Result  `json:"result"`
	Saved  string          `json:"saved,omitempty"`
}

type getViewReport struct {
	Vantage string         `json:"vantage"`
	Via     string         `json:"via"`
	View    *probe.GetView `json:"view,omitempty"`
	Error   string         `json:"error,omitempty"`
}

func runGet(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runGetWith(ctx, args, stdout, stderr, nil)
}

func runGetWith(ctx context.Context, args []string, stdout, stderr io.Writer, c *common) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if c == nil {
		c = &common{}
	}
	c.register(fs)
	out := fs.String("o", "", "save the file here, only if the verdict is clean (AGREE or MATCH)")
	expect := fs.String("expect", "", "SHA-256 (hex) the file must have")
	maxSize := fs.Int64("max-size", 64<<20, "largest file accepted, in bytes (each vantage point downloads it in full)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: nymvantage get [options] https://URL\n\nDownload URL through several Nym vantage points at once and compare the bytes, so a server can't\nhand you (or an exit) a different file than everyone else gets. Made for checksum files, signatures,\nrelease manifests and other small files that must be the same for everyone.\n\nOptions:")
		fs.PrintDefaults()
	}
	if err := parseInterspersed(fs, args); err != nil || fs.NArg() != 1 {
		if err == nil {
			fs.Usage()
		}
		return 3
	}
	url := fs.Arg(0)
	if !strings.HasPrefix(url, "https://") {
		fmt.Fprintln(stderr, "error: only https:// URLs")
		return 3
	}
	if *expect != "" {
		e := strings.ToLower(strings.TrimPrefix(*expect, "sha256:"))
		if b, err := hex.DecodeString(e); err != nil || len(b) != 32 {
			fmt.Fprintln(stderr, "error: --expect needs a SHA-256 in hex (64 characters)")
			return 3
		}
		*expect = e
	}
	if *expect != "" && c.local {
		fmt.Fprintln(stderr, "error: use --expect or --local, not both")
		return 3
	}
	roots, err := c.roots()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	tmp, err := os.MkdirTemp(c.tmp, "nymvantage-get-")
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	defer os.RemoveAll(tmp)

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	set, local, err := c.vantages(ctx, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	defer set.Close()
	if !c.jsonOut {
		header(stdout, "get "+url, c, set)
	}
	mix, loc := each(ctx, set, local, func(ctx context.Context, d probe.DialFunc) (*probe.GetView, error) {
		v, err := probe.Get(ctx, d, url, *maxSize, roots, tmp)
		if err == nil && v.Status != 200 {
			return v, fmt.Errorf("HTTP %d", v.Status)
		}
		return v, err
	})
	set.Close()

	rep := getReport{URL: url, Expect: *expect}
	obs := make([]verdict.Obs, len(mix))
	for i, a := range mix {
		rep.Views = append(rep.Views, getViewReport{Vantage: a.V.Name, Via: a.V.Label, View: a.View, Error: errText(a.Err)})
		obs[i] = verdict.Obs{Vantage: a.V.Name, Err: a.Err}
		if a.Err == nil {
			obs[i].Key = a.View.SHA256
		}
	}
	var ref *verdict.Ref
	if loc != nil {
		rep.Local = &getViewReport{Vantage: "local", Via: loc.V.Label, View: loc.View, Error: errText(loc.Err)}
		ref = &verdict.Ref{Name: "your direct download", Err: loc.Err}
		if loc.Err == nil {
			ref.Key = loc.View.SHA256
		}
	}
	if *expect != "" {
		ref = &verdict.Ref{Name: "--expect", Key: *expect}
	}
	res := verdict.Decide(obs, c.quorumOr(), ref)
	rep.Result = res

	if *out != "" && res.Code.Exit() == 0 {
		var src string
		for _, a := range mix {
			if a.Err == nil {
				src = a.View.File
				break
			}
		}
		if err := saveFile(src, *out); err != nil {
			fmt.Fprintln(stderr, "error: saving:", err)
			return 2
		}
		rep.Saved = *out
	}

	if c.jsonOut {
		writeJSON(stdout, rep)
		return res.Code.Exit()
	}
	for _, v := range rep.Views {
		printGetView(stdout, v)
	}
	if rep.Local != nil {
		printGetView(stdout, *rep.Local)
	}
	fmt.Fprintf(stdout, "verdict: %s: %s\n", res.Code, res.Reason)
	if res.Agreed != "" {
		fmt.Fprintf(stdout, "  sha256 %s\n", res.Agreed)
	}
	switch {
	case rep.Saved != "":
		fmt.Fprintf(stdout, "saved %s\n", rep.Saved)
	case *out != "":
		fmt.Fprintf(stdout, "not saved: the verdict is not clean\n")
	}
	return res.Code.Exit()
}

// saveFile copies src to dst through a temporary file in dst's directory, so
// dst never holds a partial file.
func saveFile(src, dst string) error {
	if src == "" {
		return errors.New("no body")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".nymvantage-")
	if err != nil {
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func printGetView(w io.Writer, r getViewReport) {
	fmt.Fprintf(w, "  %-8s %-26s ", r.Vantage, r.Via)
	if r.Error != "" || r.View == nil {
		fmt.Fprintf(w, "no answer: %s\n", r.Error)
		return
	}
	fmt.Fprintf(w, "sha256 %s  %d bytes  [%.1fs]\n", probe.ShortHex(r.View.SHA256), r.View.Size, r.View.Took)
}
