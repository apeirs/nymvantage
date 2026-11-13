package nym

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeClient is a stand-in nym-socks5-client: `init` writes a config under
// $HOME/.nym (and records $HOME), `run` prints the ready line and sleeps.
const fakeClient = `#!/bin/sh
set -eu
case "$1" in
init)
  d="$HOME/.nym/socks5-clients/nymvantage/config"; mkdir -p "$d"
  printf "credentials_database = '%s/credentials_database.db'\n" "$HOME/x" > "$d/config.toml"
  echo "$HOME" > "$REC/home"; echo "$*" > "$REC/init-args"
  ;;
run)
  echo "$$" > "$REC/pid"
  echo "Client startup finished!"
  exec sleep 60
  ;;
esac
`

func TestEphemeralIsPrivateAndCleanedUp(t *testing.T) {
	rec := t.TempDir()
	bin := filepath.Join(t.TempDir(), "nym-socks5-client")
	if err := os.WriteFile(bin, []byte(fakeClient), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REC", rec)
	t.Setenv("HTTPS_PROXY", "http://should-not-pass:3128")
	// A decoy $HOME: if the child ever inherited it, the fake client writes
	// there instead of into the user's real ~/.nym.
	t.Setenv("HOME", t.TempDir())
	base := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	e, err := StartEphemeral(ctx, bin, ExitProvider{NodeID: 7, Address: "prov.addr@gw"}, base)
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.ReadFile(filepath.Join(rec, "home"))
	if strings.TrimSpace(string(home)) != e.Dir() || !strings.HasPrefix(e.Dir(), base) {
		t.Fatalf("client HOME %q, ephemeral dir %q", home, e.Dir())
	}
	if st, _ := os.Stat(e.Dir()); st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode().Perm())
	}
	args, _ := os.ReadFile(filepath.Join(rec, "init-args"))
	for _, want := range []string{"--provider prov.addr@gw", "--use-reply-surbs true", "--port " + strings.Split(e.Proxy, ":")[1]} {
		if !strings.Contains(string(args), want) {
			t.Errorf("init args %q lack %q", args, want)
		}
	}
	cfg, _ := os.ReadFile(filepath.Join(e.Dir(), ".nym/socks5-clients/nymvantage/config/config.toml"))
	if !strings.Contains(string(cfg), "credential_requests_database") {
		t.Errorf("config not patched: %s", cfg)
	}
	pidb, _ := os.ReadFile(filepath.Join(rec, "pid"))
	var pid int
	for _, c := range strings.TrimSpace(string(pidb)) {
		pid = pid*10 + int(c-'0')
	}
	e.Close()
	if _, err := os.Stat(e.Dir()); !os.IsNotExist(err) {
		t.Errorf("identity dir left behind: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if pid > 0 && syscall.Kill(pid, 0) == nil {
		t.Errorf("client process %d still running", pid)
	}
}

func TestEphemeralStartupFailureCleansUp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	bin := filepath.Join(t.TempDir(), "nym-socks5-client")
	os.WriteFile(bin, []byte("#!/bin/sh\n[ \"$1\" = init ] && exit 0\necho boom; exit 3\n"), 0o755)
	base := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := StartEphemeral(ctx, bin, ExitProvider{Address: "x"}, base); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	if ents, _ := os.ReadDir(base); len(ents) != 0 {
		t.Errorf("left %d entries in %s", len(ents), base)
	}
}

func TestCleanEnv(t *testing.T) {
	got := cleanEnv([]string{"HOME=/root", "PATH=/bin", "https_proxy=x", "ALL_PROXY=y", "LANG=C"})
	if strings.Join(got, " ") != "PATH=/bin LANG=C" {
		t.Errorf("got %v", got)
	}
}
