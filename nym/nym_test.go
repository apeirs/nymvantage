package nym

import (
	"strings"
	"testing"
)

const cfg = `[storage_paths]
keys_dir = '/h/.nym/socks5-clients/nymvantage/data'
credentials_database = '/h/.nym/socks5-clients/nymvantage/data/credentials_database.db'
reply_surb_database = '/h/.nym/socks5-clients/nymvantage/data/persistent_reply_store.sqlite'
`

func TestPatchConfigText(t *testing.T) {
	changed, out := PatchConfigText(cfg)
	if !changed || !strings.Contains(out, "credential_requests_database = '/h/.nym/socks5-clients/nymvantage/data/credential_requests.db'\n") {
		t.Fatalf("not patched:\n%s", out)
	}
	if changed, again := PatchConfigText(out); changed || again != out {
		t.Fatal("patch is not idempotent")
	}
}

func TestPickDistinct(t *testing.T) {
	ps := []ExitProvider{
		{NodeID: 1, Country: "DE"}, {NodeID: 2, Country: "DE"}, {NodeID: 3, Country: "DE"},
		{NodeID: 4, Country: "FR"}, {NodeID: 5, Country: "NL"}, {NodeID: 6, Country: ""},
	}
	for range 200 {
		got, err := PickDistinct(ps, 3)
		if err != nil || len(got) != 3 {
			t.Fatal(got, err)
		}
		nodes, countries := map[int]bool{}, map[string]bool{}
		for _, p := range got {
			if nodes[p.NodeID] {
				t.Fatalf("node %d picked twice: %v", p.NodeID, got)
			}
			nodes[p.NodeID] = true
			if p.Country != "" && countries[p.Country] {
				t.Fatalf("country %s picked twice although others were free: %v", p.Country, got)
			}
			countries[p.Country] = true
		}
	}
	// More vantage points than countries: countries repeat, nodes never do.
	got, err := PickDistinct(ps, 6)
	if err != nil || len(got) != 6 {
		t.Fatal(got, err)
	}
	seen := map[int]bool{}
	for _, p := range got {
		if seen[p.NodeID] {
			t.Fatal("node repeated")
		}
		seen[p.NodeID] = true
	}
	if _, err := PickDistinct(ps, 7); err == nil {
		t.Error("asked for more exits than exist")
	}
	if _, err := PickDistinct(nil, 1); err == nil {
		t.Error("empty list")
	}
	// The choice is random, not the first n.
	first := map[int]int{}
	for range 300 {
		got, _ := PickDistinct(ps, 1)
		first[got[0].NodeID]++
	}
	if len(first) < 4 {
		t.Errorf("not random: %v", first)
	}
}
