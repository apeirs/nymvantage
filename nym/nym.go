// Package nym sets up and runs the official nym-socks5-client release binary.
//
// nymvantage does not reimplement the mixnet. Nym's own client does the Sphinx
// packet construction, cover traffic, Poisson delays and gateway handling, and
// exposes a SOCKS5 port that nymvantage talks to.
package nym

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const NymAPI = "https://validator.nymtech.net/api"

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// FindBinary locates nym-socks5-client: explicit path, $NYMVANTAGE_NYM_SOCKS5, then $PATH.
func FindBinary(explicit string) (string, error) {
	cands := []string{explicit, os.Getenv("NYMVANTAGE_NYM_SOCKS5")}
	if p, err := exec.LookPath("nym-socks5-client"); err == nil {
		cands = append(cands, p)
	}
	for _, c := range cands {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", errors.New("nym-socks5-client not found. Download it from https://github.com/nymtech/nym/releases " +
		"(nym-binaries-*), check its sha256 against the release's hashes.json, chmod +x it, then pass " +
		"--binary PATH or set NYMVANTAGE_NYM_SOCKS5")
}

// ExitProvider is a network requester on an active exit gateway.
type ExitProvider struct {
	NodeID      int      `json:"node_id"`
	Country     string   `json:"country"`
	Performance float64  `json:"performance"`
	Version     string   `json:"version"`
	Address     string   `json:"address"`
	IPs         []string `json:"ips"`
}

func getJSON(url string, v any) error {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	c := &http.Client{Timeout: 90 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// num accepts a JSON number or a numeric string.
type num float64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	f, err := strconv.ParseFloat(s, 64)
	*n = num(f)
	return err
}

// ListExitProviders asks the nym-api for network requesters on currently
// active exit gateways that enforce the exit policy.
//
// This queries the public nym-api directly (not through the mixnet), exactly
// as nym-socks5-client itself does to fetch the network topology. It reveals
// that you use Nym, nothing about which servers you ask.
func ListExitProviders(api string, minPerf float64) ([]ExitProvider, error) {
	var skimmed struct {
		Nodes struct {
			Data []struct {
				NodeID      int    `json:"node_id"`
				Role        string `json:"role"`
				Performance num    `json:"performance"`
			} `json:"data"`
		} `json:"nodes"`
	}
	if err := getJSON(api+"/v1/unstable/nym-nodes/skimmed/exit-gateways/all", &skimmed); err != nil {
		return nil, err
	}
	desc, err := Described(api)
	if err != nil {
		return nil, err
	}
	var out []ExitProvider
	for _, n := range skimmed.Nodes.Data {
		if n.Role != "ExitGateway" || float64(n.Performance) < minPerf {
			continue
		}
		d, ok := desc[n.NodeID]
		if !ok || d.Description.NetworkRequester == nil || d.Description.NetworkRequester.Address == "" || !d.Description.NetworkRequester.UsesExitPolicy {
			continue
		}
		out = append(out, ExitProvider{
			NodeID:      n.NodeID,
			Country:     d.Description.Aux.Location,
			Performance: float64(n.Performance),
			Version:     d.Description.Build.Version,
			Address:     d.Description.NetworkRequester.Address,
			IPs:         d.Description.Host.IPs,
		})
	}
	return out, nil
}

// DescribedNode is the subset of /v1/nym-nodes/described we use.
type DescribedNode struct {
	NodeID      int `json:"node_id"`
	Description struct {
		Host struct {
			IPs []string `json:"ip_address"`
		} `json:"host_information"`
		NetworkRequester *struct {
			Address        string `json:"address"`
			UsesExitPolicy bool   `json:"uses_exit_policy"`
		} `json:"network_requester"`
		Aux struct {
			Location string `json:"location"`
		} `json:"auxiliary_details"`
		Build struct {
			Version string `json:"build_version"`
		} `json:"build_information"`
		Roles struct {
			ExitNR bool `json:"exit_nr"`
		} `json:"declared_role"`
	} `json:"description"`
}

// Described returns every node the nym-api describes, keyed by node id.
func Described(api string) (map[int]DescribedNode, error) {
	var d struct {
		Data []DescribedNode `json:"data"`
	}
	if err := getJSON(api+"/v1/nym-nodes/described?per_page=5000", &d); err != nil {
		return nil, err
	}
	m := make(map[int]DescribedNode, len(d.Data))
	for _, n := range d.Data {
		m[n.NodeID] = n
	}
	return m, nil
}

// NodeByIP finds which Nym node announces ip (used to show that a server saw
// a Nym exit gateway's address).
func NodeByIP(api, ip string) (*DescribedNode, error) {
	desc, err := Described(api)
	if err != nil {
		return nil, err
	}
	for _, n := range desc {
		for _, a := range n.Description.Host.IPs {
			if a == ip {
				n := n
				return &n, nil
			}
		}
	}
	return nil, nil
}

// PickDistinct chooses n different exit providers at random, in n different
// countries when the list allows it (then repeats countries, never nodes).
// Random choice spreads load and keeps the vantage points unpredictable, so a
// server cannot prepare a "clean" answer for the exits a checker will use.
func PickDistinct(ps []ExitProvider, n int) ([]ExitProvider, error) {
	if len(ps) == 0 {
		return nil, errors.New("nym-api lists no active exit gateway with a network requester")
	}
	if n > len(ps) {
		return nil, fmt.Errorf("asked for %d vantage points, but the nym-api lists only %d usable exit gateways", n, len(ps))
	}
	order := rand.Perm(len(ps))
	var out []ExitProvider
	used := map[int]bool{}
	countries := map[string]bool{}
	// First pass: one per country (an empty country counts as unknown, never "the same").
	for _, i := range order {
		if len(out) == n {
			break
		}
		c := ps[i].Country
		if c != "" && countries[c] {
			continue
		}
		countries[c] = c != ""
		used[i] = true
		out = append(out, ps[i])
	}
	for _, i := range order {
		if len(out) == n {
			break
		}
		if !used[i] {
			used[i] = true
			out = append(out, ps[i])
		}
	}
	return out, nil
}

var (
	reCredReq = regexp.MustCompile(`(?m)^credential_requests_database\s*=`)
	reCredDB  = regexp.MustCompile(`(?m)^credentials_database = '(.*)/credentials_database\.db'\s*$`)
)

// PatchConfigText works around nym-socks5-client 1.1.86 (v2026.19) writing a
// config it can't read: the template omits credential_requests_database while
// the loader requires it, so `run` fails right after `init` with
// "missing field `credential_requests_database`". Adds the default path.
func PatchConfigText(text string) (bool, string) {
	if reCredReq.MatchString(text) {
		return false, text
	}
	loc := reCredDB.FindStringSubmatchIndex(text)
	if loc == nil {
		return false, text
	}
	dir := text[loc[2]:loc[3]]
	line := "\ncredential_requests_database = '" + dir + "/credential_requests.db'"
	return true, text[:loc[1]] + line + text[loc[1]:]
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
