# nymvantage

See what the rest of the world sees, through the [Nym mixnet](https://nym.com).

`nymvantage` looks at a server from several independent points on the Nym mixnet at once. Each point is a new,
throwaway Nym client using a different exit gateway, in a different country where possible. It then compares what
they were shown:

- `nymvantage tls HOST`: the TLS certificate. Add `--local` to compare it with what your own connection gets.
  A captive portal, an antivirus or corporate TLS proxy, or an ISP or state that intercepts TLS shows up as a
  **MISMATCH**.
- `nymvantage ssh HOST`: the SSH host keys (no login is attempted), checked against your `~/.ssh/known_hosts`.
  `--add` writes them there only if every vantage point saw the same keys. This solves the blind "first connect"
  (trust on first use) problem.
- `nymvantage get URL`: downloads the file through every vantage point and saves it only if all of them got the
  same bytes (optionally `--expect SHA256`). This catches a server or mirror that hands one visitor a different
  `SHA256SUMS`, signature or release manifest.

It is the Nym counterpart of the "notary" tools from the Tor world,
[Perspectives](https://www.usenix.org/legacy/event/usenix08/tech/full_papers/wendlandt/wendlandt.pdf) and
DetecTor, which compare a certificate seen from several Tor circuits.

```
$ nymvantage tls torproject.org --local
tls torproject.org:443 (SNI torproject.org): 3 vantage points through the Nym mixnet, each a new Nym client and a different exit gateway, plus your direct connection
  nym-1    exit node 3242 (RO)        cert 74b1b6600d3433c0  key 1599b2352ee91049  issuer "YR2"  until 2026-12-22  trusted  [1.1s]
  nym-2    exit node 3047 (GB)        cert 74b1b6600d3433c0  key 1599b2352ee91049  issuer "YR2"  until 2026-12-22  trusted  [1.1s]
  nym-3    exit node 2644 (SE)        cert 74b1b6600d3433c0  key 1599b2352ee91049  issuer "YR2"  until 2026-12-22  trusted  [1.4s]
  local    your direct connection     cert 74b1b6600d3433c0  key 1599b2352ee91049  issuer "YR2"  until 2026-12-22  trusted  [0.3s]
verdict: MATCH (compared by certificate): your direct connection matches what 3 of 3 mixnet vantage points saw
```

## Why the mixnet

You could ask from three VPNs instead. On the mixnet, though:

- **The server can't tell the checks apart from ordinary visitors.** Every vantage point is a new mixnet identity
  that is never reused, so a server or mirror can't spot "the checker" and hand only the checker the clean answer.
  It sees N unrelated anonymous visitors.
- **No single operator sees the whole check.** Each vantage point goes through a different exit gateway, and the
  mixnet hides from every exit who is asking. No party sees all of the queries, or links them to you.
- **There are many independent exits.** The nym-api lists about 100 exit gateways with a network requester, in
  about 40 countries (`nymvantage exits`), run by independent operators.

## Verdicts and exit status

| verdict | meaning | exit |
|---|---|---|
| `AGREE` | every mixnet vantage point that answered saw the same (at least `--quorum`, default 2) | 0 |
| `MATCH` | they agree, and your direct connection (`--local`), known_hosts or `--expect` matches | 0 |
| `SPLIT` | the mixnet vantage points were shown different things | 1 |
| `MISMATCH` | they agree with each other, but not with you / known_hosts / `--expect` | 1 |
| `INCONCLUSIVE` | too few vantage points answered, or your side gave no answer | 2 |

A missing answer is never treated as fine. Usage errors exit with 3. `--json` prints the full result: every view,
the groups of vantage points that agreed, and the reason.

**CDNs.** Big sites serve different certificates from different edges. When the certificates differ but all come
from the same CA key (Authority Key Identifier) and all verify, `tls` compares by issuing CA and says so in a note.
`--strict` turns this off.

**The same broken certificate everywhere** (expired, wrong name, unknown CA) is consistent, so the verdict is
`AGREE`. A note says it is the server's own problem and not interception on your path.

## How it uses Nym

- Each vantage point is a new `nym-socks5-client` with a fresh identity, kept in a private temporary directory
  under its own `$HOME`. It uses one exit gateway (network requester) chosen from the nym-api's list, with
  performance ≥ 0.95 by default and distinct countries first, and reply SURBs. The clients start in parallel, in
  about 2-4 s. A client that fails to start is replaced by one on a spare exit. All of them are stopped, and their
  identities deleted, as soon as the answers are in. They also die with nymvantage (Pdeathsig).
- Every connection is a SOCKS5 CONNECT by **host name** (ATYP 3). The exit resolves the name, so there is no local
  DNS lookup. There is no other dialer: if a Nym client is down, that vantage point simply has no answer. Nothing
  falls back to a direct connection.
- The only non-mixnet traffic nymvantage sends is your own connection when you ask for it with `--local`, and the
  nym-api request for the list of exits (see Limits).
- Nym's exit policy allows the ports that matter here: 22, 443, 465, 587, 853, 993, 995 and 8443, among others.

## Install

You need Go 1.26+ and Nym's `nym-socks5-client` release binary
([nymtech/nym releases](https://github.com/nymtech/nym/releases), the `nym-socks5-client` asset for your
platform).

```sh
go install github.com/apeirs/nymvantage/cmd/nymvantage@latest
install -m 755 nym-socks5-client ~/.local/bin/              # or anywhere on $PATH
export NYMVANTAGE_NYM_SOCKS5=~/.local/bin/nym-socks5-client  # if it is not on $PATH
```

## Usage

```sh
# Is my TLS being intercepted (hotel wifi, work laptop, a country that does it)?
nymvantage tls example.org --local

# First SSH connection to a new server: check its keys, then trust them
nymvantage ssh git.example.org            # prints known_hosts lines if all vantage points agree
nymvantage ssh git.example.org --add      # ...and appends them (--hash for hashed names)
ssh git.example.org                       # no "authenticity can't be established" prompt

# Download a checksum file only if everyone gets the same one
nymvantage get https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc -o sha256sums.asc
nymvantage get https://example.org/release.tar.gz --expect 3f1c...e9 -o release.tar.gz

# More vantage points, a stricter quorum, JSON for scripts
nymvantage tls example.org -n 5 --quorum 4 --json
```

Options common to `tls`, `ssh` and `get`:

| option | |
|---|---|
| `-n N` | number of mixnet vantage points (default 3) |
| `--quorum K` | answers needed for a verdict (default 2, or N if N < 2) |
| `--local` | also ask over your own direct connection and compare it |
| `--proxy HOST:PORT` | use a Nym SOCKS5 client you run instead of starting new ones (repeat it) |
| `--probe-timeout` | give up on one vantage point after this long (tls, ssh; default 45s) |
| `--timeout` | give up on the whole check (default 3m) |
| `--min-performance` | skip exit gateways below this score (default 0.95) |
| `--binary`, `--nym-api`, `--tmpdir`, `--ca-file`, `--json`, `-v` | see `nymvantage CMD -h` |

### Many checks: keep the clients running

```sh
nymvantage clients -n 3      # starts 3 clients on different exits, prints the --proxy flags, Ctrl-C stops them
nymvantage tls a.example --proxy 127.0.0.1:41511 --proxy 127.0.0.1:38207 --proxy 127.0.0.1:45763
```

This saves the 2-4 s start-up per check. The trade-off: checks that share these clients also share their exits,
so an exit can link those checks to each other (though not to you). With `--proxy`, nymvantage can't check that
the clients use different exits.

## Threat model

nymvantage detects a difference between what one path is shown and what other paths are shown:

- **On your path** (`--local`): TLS interception by a captive portal, middlebox, antivirus, employer, ISP or state;
  an SSH man in the middle on first connect; a download swapped in transit or targeted at your IP.
- **On one vantage point's path, or targeted at one visitor**: shows up as `SPLIT`. That includes a server or mirror
  that sometimes serves a different file, and an exit gateway that tampers with its own traffic.

It does **not** detect:

- An attacker at or next to the server, or the server itself giving everyone the same bad answer. Every vantage
  point then agrees. A mis-issued certificate served to everyone falls under this too; it is the notary model's
  known blind spot, which Certificate Transparency covers.
- An attacker who controls a majority of the chosen exits **and** your path at the same time.
- A server that treats all Nym exits alike (it can see they are Nym exits) and also your connection differently from
  them. Then `--local` reports `MISMATCH`, which is still the right alarm: you get told your view is not the
  common one.

## Limits

- **The exit list is fetched directly** from the nym-api over HTTPS (`nymvantage exits`). That tells the nym-api's
  host that this IP runs a Nym app, but not what it checks. To avoid it, run your own clients and use `--proxy`.
- **Only the ports Nym's exit policy allows.** Other ports are refused at the exit, so the vantage point has no
  answer and the result is `INCONCLUSIVE`.
- **Fingerprintable as a Go client.** Go's TLS ClientHello and SSH banner (`SSH-2.0-Go`) differ from a browser's or
  OpenSSH's. A server that serves differently by client type can tell nymvantage apart from browsers, though not one
  nymvantage user from another.
- **`tls` compares the leaf certificate and its issuing CA**, not the whole chain, OCSP or the TLS version. **`ssh`**
  asks for ed25519, ecdsa-p256 and rsa keys (`--all-types` adds p384/p521). DSA isn't supported.
- **`get` is for small files** (default cap 64 MiB): every vantage point downloads the whole file through the
  mixnet. It accepts https:// only, and only https redirects. It sends no User-Agent, cookies or auth. A non-200
  answer counts as no answer.
- **Speed.** A check typically takes 5-15 s. A slow exit costs up to `--probe-timeout`.
- **Not audited.** Version 0.1.

## Proof it works (Nym mainnet, logs in `examples/`)

- `live-tls.txt`: torproject.org (MATCH with the direct view; one exit stalled and was cut off at
  `--probe-timeout`), www.google.com and imap.gmail.com:993 (different edge certificates, the CDN rule), github.com
  from 4 exits, expired.badssl.com (the same broken certificate everywhere, with the note), JSON output.
- `live-ssh.txt`: github.com host keys from 3 exits, the same as GitHub's published fingerprints; known_hosts
  lines; `--add`; a second run that MATCHes the new known_hosts; gitlab.com as JSON; and a known_hosts entry
  holding another server's key, giving MISMATCH with the file left untouched.
- `live-get.txt`: Debian's `Release` file and kernel.org's `sha256sums.asc` (3 and 4 exits), `--expect`, and a
  wrong `--expect` that is refused and not saved.
- `live-netns.txt` (`examples/netns-check.sh`): nymvantage inside a network namespace with **no route out**, where
  its only way out is the Nym clients on the host, bridged in through Unix sockets. tls, ssh and get all work. A
  direct connection, local DNS and `--local` all fail, and with the clients gone it ends `INCONCLUSIVE` with no
  fallback.

## Tests

```sh
go test ./...                    # no network: fake Nym SOCKS5 clients, fake TLS and SSH servers
python3 examples/mutate.py .     # breaks 29 guards one at a time; each must make a test fail
```

The tests cover:

- the verdict rules: split, quorum, the CDN rule, `--strict`, and the same CA with a wrong name;
- that nothing falls back to direct: with the Nym clients down, the target servers receive zero connections;
- the SSH probe never tries to log in;
- known_hosts lines that `ssh` accepts, including hashed names and non-default ports;
- files are saved only on a clean verdict;
- distinct exits, and clients replaced and stopped exactly once.

`examples/mutations.txt` holds the last run: 29 of 29 caught.

## License

MIT
