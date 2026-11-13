#!/bin/sh
# Run nymvantage inside a network namespace with no route to the internet.
# The only way out is one Unix socket per Nym client running on the host, so
# every answer came through the mixnet: a direct connection or a local DNS
# lookup from nymvantage would simply fail.
#
# Usage: examples/netns-check.sh [path/to/nymvantage]
# Needs: unprivileged user namespaces (unshare -rn), iproute2, python3, curl,
# and nym-socks5-client ($NYMVANTAGE_NYM_SOCKS5 or $PATH).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
NV=$(realpath "${1:-$(command -v nymvantage)}")
dir=$(mktemp -d)
"$NV" clients -n 3 > "$dir/clients.txt" 2>&1 &
clients=$!
relays=""
trap 'kill $relays $clients 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$dir"' EXIT INT TERM
for _ in $(seq 180); do
	grep -q '^--proxy' "$dir/clients.txt" && break
	kill -0 $clients 2>/dev/null || { cat "$dir/clients.txt"; exit 2; }
	sleep 1
done
echo "== on the host: nymvantage clients -n 3"
grep -v '^--proxy' "$dir/clients.txt" | sed 's/^/   /'
n=0
for p in $(grep '^--proxy' "$dir/clients.txt" | sed 's/--proxy//g'); do
	n=$((n + 1))
	python3 "$here/unix-relay.py" listen-unix "$dir/nym$n.sock" "$p" &
	relays="$relays $!"
done
sleep 0.5

unshare -rn sh -eu -c '
dir=$1 here=$2 nv=$3 n=$4
ip link set lo up
proxies="" relays=""
for i in $(seq "$n"); do
	python3 "$here/unix-relay.py" listen-tcp "127.0.0.1:$((1080 + i))" "$dir/nym$i.sock" >/dev/null 2>&1 &
	relays="$relays $!"
	proxies="$proxies --proxy 127.0.0.1:$((1080 + i))"
done
trap "kill \$relays 2>/dev/null || true" EXIT
for i in $(seq "$n"); do
	for _ in $(seq 20); do python3 -c "import socket; socket.create_connection((\"127.0.0.1\", $((1080 + i)))).close()" 2>/dev/null && break; sleep 0.2; done
done
run() { echo; echo "== nymvantage $*"; { "$nv" "$@" 2>&1 && echo "[exit 0]" || echo "[exit $?]"; } | sed "s/^/   /"; }

echo
echo "== inside: this namespace has no route out"
ip -br addr | sed "s/^/   /"
curl -sS --max-time 5 -o /dev/null https://1.1.1.1/ 2>&1 | sed "s/^/   /" || true
getent hosts github.com >/dev/null 2>&1 && echo "   local DNS works (unexpected)" || echo "   local DNS: no answer"

run tls torproject.org $proxies
run ssh github.com --known-hosts "" $proxies
run get https://deb.debian.org/debian/dists/stable/Release $proxies
echo
echo "== --local in here: your own connection has no route, so there is nothing to compare with;"
echo "   that is INCONCLUSIVE, never replaced by a mixnet answer"
run tls torproject.org --local $proxies
echo
echo "== the Nym clients gone (nothing listens on these ports): no fallback, it just fails"
run tls torproject.org --proxy 127.0.0.1:1 --proxy 127.0.0.1:2 --proxy 127.0.0.1:3
' sh "$dir" "$here" "$NV" "$n"
