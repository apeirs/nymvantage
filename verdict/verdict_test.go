package verdict

import (
	"errors"
	"testing"
)

func obs(keys ...string) []Obs {
	var out []Obs
	for i, k := range keys {
		o := Obs{Vantage: string(rune('a' + i)), Key: k}
		if k == "" {
			o.Err = errors.New("no answer")
		}
		out = append(out, o)
	}
	return out
}

func TestDecide(t *testing.T) {
	failed := errors.New("unreachable")
	cases := []struct {
		name   string
		obs    []Obs
		quorum int
		ref    *Ref
		want   Code
	}{
		{"all agree", obs("x", "x", "x"), 2, nil, Agree},
		{"one missing, quorum met", obs("x", "", "x"), 2, nil, Agree},
		{"split", obs("x", "y", "x"), 2, nil, Split},
		{"split even if below quorum", obs("x", "y", ""), 3, nil, Split},
		{"too few answers", obs("x", "", ""), 2, nil, Inconclusive},
		{"nobody answered", obs("", "", ""), 1, nil, Inconclusive},
		{"no vantage points at all", nil, 1, nil, Inconclusive},
		{"ref matches", obs("x", "x", "x"), 2, &Ref{Name: "local", Key: "x"}, Match},
		{"ref differs", obs("x", "x", "x"), 2, &Ref{Name: "local", Key: "evil"}, Mismatch},
		{"ref failed", obs("x", "x", "x"), 2, &Ref{Name: "local", Err: failed}, Inconclusive},
		{"split beats ref", obs("x", "y", "x"), 2, &Ref{Name: "local", Key: "x"}, Split},
		{"too few answers beats ref", obs("x", "", ""), 2, &Ref{Name: "local", Key: "x"}, Inconclusive},
	}
	for _, c := range cases {
		r := Decide(c.obs, c.quorum, c.ref)
		if r.Code != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, r.Code, r.Reason, c.want)
		}
		if r.Code == Agree || r.Code == Match {
			if r.Agreed != "x" {
				t.Errorf("%s: agreed %q", c.name, r.Agreed)
			}
		}
	}
}

func TestExitAndWorst(t *testing.T) {
	if Agree.Exit() != 0 || Match.Exit() != 0 || Split.Exit() != 1 || Mismatch.Exit() != 1 || Inconclusive.Exit() != 2 {
		t.Fatal("exit codes")
	}
	if Worst() != Inconclusive {
		t.Error("no codes must not be fine")
	}
	if Worst(Agree, Inconclusive, Match) != Inconclusive {
		t.Error("missing answer must outrank a clean result")
	}
	if Worst(Inconclusive, Mismatch, Agree).Exit() != 1 {
		t.Error("a difference must outrank a missing answer")
	}
	if Worst(Match, Match) != Match || Worst(Match, Agree) != Agree {
		t.Error("MATCH overall only if every part matched")
	}
	if Worst(Agree, Match).Exit() != 0 {
		t.Error("clean + clean")
	}
}
