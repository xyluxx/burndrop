package storage

import (
	"context"
	"sort"
)

// Candidate is one backend with its probe result, for first-run detection.
type Candidate struct {
	Backend Backend
	Probe   Probe
}

// Detect probes every backend in candidates and returns them ordered from
// strongest available to weakest, with unavailable ones last. It never
// stores anything.
func Detect(ctx context.Context, candidates []Backend) []Candidate {
	out := make([]Candidate, 0, len(candidates))
	for _, b := range candidates {
		if b == nil {
			continue
		}
		if ctx.Err() != nil {
			out = append(out, Candidate{Backend: b, Probe: Probe{Reason: "detection cancelled"}})
			continue
		}
		out = append(out, Candidate{Backend: b, Probe: b.Probe(ctx)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Probe.Available != b.Probe.Available {
			return a.Probe.Available
		}
		return a.Probe.Rank > b.Probe.Rank
	})
	return out
}

// Recommend returns the strongest available candidate, or nil.
func Recommend(candidates []Candidate) *Candidate {
	for i := range candidates {
		if candidates[i].Probe.Available {
			return &candidates[i]
		}
	}
	return nil
}
