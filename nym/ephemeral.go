package nym

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Ephemeral is a throwaway nym-socks5-client: a new mixnet identity (new keys,
// a gateway picked by the client, the exit given by the caller) that lives in
// a private temporary directory and is deleted on Close. nymvantage starts one
// per vantage point, so the server being checked sees unrelated Nym users,
// and no gateway or exit takes part in more than one of the checks.
type Ephemeral struct {
	Proxy    string        // 127.0.0.1:port of its SOCKS5 listener
	Provider ExitProvider  // the exit gateway's network requester it uses
	Startup  time.Duration // init + run until "Client startup finished"

	dir  string
	cmd  *exec.Cmd
	once sync.Once
	done chan struct{}
}

// freePort asks the kernel for an unused loopback port.
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// StartEphemeral initialises and runs a fresh client for provider p. The
// release binary keeps its state in $HOME/.nym and ignores $NYM_HOME, so the
// child gets HOME set to a new 0700 directory under base ("" = os.TempDir()).
func StartEphemeral(ctx context.Context, binary string, p ExitProvider, base string) (*Ephemeral, error) {
	t0 := time.Now()
	dir, err := os.MkdirTemp(base, "nymvantage-eph-")
	if err != nil {
		return nil, err
	}
	e := &Ephemeral{Provider: p, dir: dir, done: make(chan struct{})}
	fail := func(err error) (*Ephemeral, error) {
		e.Close()
		return nil, err
	}
	port, err := freePort()
	if err != nil {
		return fail(err)
	}
	e.Proxy = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	env := append(cleanEnv(os.Environ()), "HOME="+dir)

	const id = "nymvantage"
	initCmd := exec.CommandContext(ctx, binary, "init", "--id", id, "--provider", p.Address,
		"--port", strconv.Itoa(port), "--use-reply-surbs", "true")
	initCmd.Env = env
	out, err := initCmd.CombinedOutput()
	if err != nil {
		return fail(fmt.Errorf("nym-socks5-client init: %v\n%s", err, tail(ansi.ReplaceAllString(string(out), ""), 1500)))
	}
	cfg := filepath.Join(dir, ".nym", "socks5-clients", id, "config", "config.toml")
	if b, err := os.ReadFile(cfg); err == nil {
		if changed, patched := PatchConfigText(string(b)); changed {
			if err := os.WriteFile(cfg, []byte(patched), 0o600); err != nil {
				return fail(err)
			}
		}
	}

	logPath := filepath.Join(dir, "run.log")
	logf, err := os.Create(logPath)
	if err != nil {
		return fail(err)
	}
	e.cmd = exec.Command(binary, "run", "--id", id)
	e.cmd.Env = env
	e.cmd.Stdout, e.cmd.Stderr = logf, logf
	e.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	if err := e.cmd.Start(); err != nil {
		logf.Close()
		return fail(err)
	}
	logf.Close()
	exited := make(chan struct{})
	go func() { _ = e.cmd.Wait(); close(exited); close(e.done) }()
	for {
		b, _ := os.ReadFile(logPath)
		if strings.Contains(string(b), "Client startup finished") {
			e.Startup = time.Since(t0)
			return e, nil
		}
		select {
		case <-exited:
			b, _ = os.ReadFile(logPath)
			return fail(fmt.Errorf("nym-socks5-client exited during startup:\n%s", tail(ansi.ReplaceAllString(string(b), ""), 1500)))
		case <-ctx.Done():
			return fail(fmt.Errorf("nym-socks5-client not ready: %w", ctx.Err()))
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// cleanEnv drops proxy variables, so the Nym client itself never tries to go
// through some other proxy the user has set for other programs.
func cleanEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "HOME", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		out = append(out, kv)
	}
	return out
}

// Close stops the client and deletes its identity and state.
func (e *Ephemeral) Close() {
	e.once.Do(func() {
		if e.cmd != nil && e.cmd.Process != nil {
			_ = syscall.Kill(-e.cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-e.done:
			case <-time.After(5 * time.Second):
				_ = syscall.Kill(-e.cmd.Process.Pid, syscall.SIGKILL)
				<-e.done
			}
		}
		_ = os.RemoveAll(e.dir)
	})
}

// Dir is the client's private directory (removed by Close).
func (e *Ephemeral) Dir() string { return e.dir }
