// Package verdict compares what the vantage points saw.
//
// The rules are deliberately plain:
//   - fewer mixnet answers than the quorum: INCONCLUSIVE (never "fine");
//   - mixnet answers that differ: SPLIT (someone is shown something else);
//   - all mixnet answers equal, and a reference (your direct connection, your
//     known_hosts, an expected hash) given: MATCH or MISMATCH;
//   - all mixnet answers equal, no reference: AGREE.
package verdict

import (
	"fmt"
	"sort"
)

// Code is the outcome of a comparison.
type Code string

const (
	Agree        Code = "AGREE"
	Match        Code = "MATCH"
	Split        Code = "SPLIT"
	Mismatch     Code = "MISMATCH"
	Inconclusive Code = "INCONCLUSIVE"
)

// Exit is the process exit status for a code: 0 fine, 1 a difference was
// seen, 2 not enough answers to say.
func (c Code) Exit() int {
	switch c {
	case Agree, Match:
		return 0
	case Split, Mismatch:
		return 1
	}
	return 2
}

// Worst combines codes: a seen difference outranks a missing answer, which
// outranks a clean result. With no codes at all there is nothing to say.
func Worst(codes ...Code) Code {
	if len(codes) == 0 {
		return Inconclusive
	}
	// A difference beats a missing answer beats a clean result, and among
	// clean results AGREE (nothing to compare with) beats MATCH: the whole is
	// MATCH only if every part matched its reference.
	rank := map[Code]int{Match: 0, Agree: 1, Inconclusive: 2, Split: 3, Mismatch: 3}
	w := codes[0]
	for _, c := range codes[1:] {
		if rank[c] > rank[w] {
			w = c
		}
	}
	return w
}

// Obs is one vantage point's answer, reduced to a comparable key.
type Obs struct {
	Vantage string
	Key     string // "" when Err is set
	Err     error
}

// Ref is the view being checked against the mixnet consensus.
type Ref struct {
	Name string // "your direct connection", "known_hosts", "--expect"
	Key  string
	Err  error // the reference could not be obtained
}

// Result is a decision with the evidence for it.
type Result struct {
	Code     Code                `json:"verdict"`
	Agreed   string              `json:"agreed,omitempty"` // the key all mixnet answers share
	Answered int                 `json:"answered"`
	Asked    int                 `json:"asked"`
	Groups   map[string][]string `json:"groups,omitempty"` // key -> vantages that saw it
	Reason   string              `json:"reason"`
}

// Decide compares mixnet observations with each other and with ref (nil = no
// reference). quorum is the least number of mixnet answers that must agree.
func Decide(obs []Obs, quorum int, ref *Ref) Result {
	r := Result{Asked: len(obs), Groups: map[string][]string{}}
	for _, o := range obs {
		if o.Err != nil {
			continue
		}
		r.Answered++
		r.Groups[o.Key] = append(r.Groups[o.Key], o.Vantage)
	}
	if quorum < 1 {
		quorum = 1
	}
	switch {
	case len(r.Groups) > 1:
		r.Code = Split
		keys := make([]string, 0, len(r.Groups))
		for k := range r.Groups {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return len(r.Groups[keys[i]]) > len(r.Groups[keys[j]]) })
		r.Reason = fmt.Sprintf("the mixnet vantage points were shown %d different answers", len(keys))
		return r
	case r.Answered < quorum:
		r.Code = Inconclusive
		r.Reason = fmt.Sprintf("only %d of %d mixnet vantage points answered; %d needed", r.Answered, r.Asked, quorum)
		return r
	}
	for k := range r.Groups {
		r.Agreed = k
	}
	if ref == nil {
		r.Code = Agree
		r.Reason = fmt.Sprintf("all %d mixnet vantage points that answered saw the same", r.Answered)
		return r
	}
	switch {
	case ref.Err != nil:
		r.Code = Inconclusive
		r.Reason = fmt.Sprintf("the mixnet vantage points agree (%d of %d), but %s gave no answer: %v", r.Answered, r.Asked, ref.Name, ref.Err)
	case ref.Key == r.Agreed:
		r.Code = Match
		r.Reason = fmt.Sprintf("%s matches what %d of %d mixnet vantage points saw", ref.Name, r.Answered, r.Asked)
	default:
		r.Code = Mismatch
		r.Reason = fmt.Sprintf("%s differs from what %d of %d mixnet vantage points saw", ref.Name, r.Answered, r.Asked)
	}
	return r
}
