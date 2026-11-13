# Break one guard at a time in a copy of the tree and check that `go test` fails.
# Usage: python3 examples/mutate.py .   (a few minutes; runs under nice)
import shutil, subprocess, sys, os, tempfile
SRC = os.path.abspath(sys.argv[1])
D, G, T, S, V, N, E = "mixnet/dialer.go", "probe/get.go", "probe/tls.go", "probe/ssh.go", "verdict/verdict.go", "nym/nym.go", "nym/ephemeral.go"
CT, CS, CG, VA = "cmd/nymvantage/tls.go", "cmd/nymvantage/ssh.go", "cmd/nymvantage/get.go", "vantage/vantage.go"
M = [
 # transport: the mixnet and nothing else
 ("direct dial instead of SOCKS5", D, "conn, err := dialSocks(ctx, d.Proxy, host, port, d.timeout())", "conn, err := (&net.Dialer{}).DialContext(ctx, \"tcp\", net.JoinHostPort(host, fmt.Sprint(port)))"),
 ("direct dial when the Nym client is down", D, "\t\treturn nil, err\n\t}\n\td.trace(\"dial %s:%d: SOCKS5", "\t\treturn (&net.Dialer{}).DialContext(ctx, \"tcp\", addr)\n\t}\n\td.trace(\"dial %s:%d: SOCKS5"),
 ("User-Agent sent on downloads", G, 'req.Header.Set("User-Agent", "")', 'req.Header.Set("User-Agent", "nymvantage/0.1")'),
 ("plain-http redirect followed", G, 'if req.URL.Scheme != "https" {', "if false {"),
 ("download TLS not verified", G, "TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},", "TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},"),
 ("no download size cap", G, "if n > maxSize {", "if false {"),
 # what counts as the same / as trusted
 ("certificate trust not checked", T, "v.Trusted = verr == nil", "v.Trusted = true"),
 ("split views ignored", V, "case len(r.Groups) > 1:", "case false:"),
 ("quorum ignored", V, "case r.Answered < quorum:", "case r.Answered < 1:"),
 ("silent reference counted as a match", V, "case ref.Err != nil:", "case false:"),
 ("CDN rule without the trust check", CT, "if ires.Code.Exit() == 0 && allTrusted {", "if ires.Code.Exit() == 0 {"),
 ("--strict ignored", CT, "&& !*strict {", "&& (!*strict || *strict) {"),
 ("download saved on an unclean verdict", CG, 'if *out != "" && res.Code.Exit() == 0 {', 'if *out != "" {'),
 ("HTTP error page counted as an answer", CG, "if err == nil && v.Status != 200 {", "if false {"),
 ("--expect ignored", CG, '\tif *expect != "" {\n\t\tref =', '\tif false {\n\t\tref ='),
 ("known_hosts lines on an unclean verdict", CS, "if rep.Verdict.Exit() == 0 {", "if true {"),
 ("known_hosts not consulted", CS, "if kh != nil && tv.Network.Code == verdict.Agree {", "if false {"),
 ("missing key type not counted", CS, "return absent, nil", "return \"\", errors.New(\"no key\")"),
 ("failed handshake counted as a missing key", CS, "if e, ok := v.Errors[t]; ok {", "if e, ok := v.Errors[t]; ok && false {"),
 ("SSH key types skipped after a timeout look absent", S, "v.Errors[KeyType(algo)] = err.Error() // not asked", "_ = err // not asked"),
 ("no per-vantage timeout", CT, "ctx, cancel := context.WithTimeout(ctx, c.probeTO)", "ctx, cancel := context.WithCancel(ctx)"),
 ("SSH goes on to log in", S, "\t\t\tgot = key\n\t\t\treturn errGotKey", "\t\t\tgot = key\n\t\t\treturn nil"),
 # vantage points: independent, throwaway
 ("exits not spread over countries", N, 'if c != "" && countries[c] {', "if false {"),
 ("failed client not replaced", VA, "np, ok := next()", "np, ok := next()\n\t\t\t\tok = false"),
 ("Nym client stopped twice", VA, "\t\tv.close = nil // stop each client once", "\t\t// stop each client once"),
 ("ephemeral client shares the user's HOME", E, 'env := append(cleanEnv(os.Environ()), "HOME="+dir)', "env := os.Environ()"),
 ("ephemeral identity not deleted", E, "_ = os.RemoveAll(e.dir)", "_ = e.dir"),
 ("ephemeral client without reply SURBs", E, '"--use-reply-surbs", "true"', '"--use-reply-surbs", "false"'),
 ("proxy env passed to the Nym client", E, 'case "HOME", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":', 'case "HOME":'),
]
# Run the tests with a throwaway $HOME, so a mutation that leaks the real
# HOME to a child process can't write into the user's ~/.nym.
GOENV = {k: subprocess.run(["go", "env", k], capture_output=True, text=True).stdout.strip()
         for k in ("GOCACHE", "GOMODCACHE", "GOPATH")}
results = []
for name, f, old, new in M:
    tmp = tempfile.mkdtemp(prefix="nymvantage-mut-")
    dst = os.path.join(tmp, "src")
    shutil.copytree(SRC, dst, ignore=shutil.ignore_patterns(".git", "examples"))
    p = os.path.join(dst, f)
    s = open(p).read()
    if s.count(old) != 1:
        results.append((name, "ANCHOR NOT FOUND (%d)" % s.count(old))); shutil.rmtree(tmp); continue
    s = s.replace(old, new)
    if "net.Dialer{}" in new and '"net"' not in s:
        s = s.replace('import (\n', 'import (\n\t"net"\n', 1)
    open(p, "w").write(s)
    env = dict(os.environ, HOME=os.path.join(tmp, "home"), **GOENV)
    os.mkdir(env["HOME"])
    r = subprocess.run(["nice", "-n", "19", "go", "test", "-count=1", "./..."], cwd=dst, env=env, capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    if r.returncode == 0:
        verdict = "SURVIVED (no test failed)"
    elif "build failed" in out or "[build failed]" in out or "setup failed" in out:
        verdict = "BUILD FAILED (mutation invalid): " + out[:300].replace("\n", " | ")
    else:
        fails = sorted({l.split()[2] for l in out.splitlines() if l.strip().startswith("--- FAIL")})
        verdict = "caught by " + ", ".join(fails) if fails else "caught (panic/timeout): " + out[-200:].replace("\n", " | ")
    results.append((name, verdict))
    shutil.rmtree(tmp)
for n, v in results:
    print(f"{n:42s} {v}")
print(f"{sum(v.startswith('caught') for _, v in results)} of {len(results)} mutations caught")
