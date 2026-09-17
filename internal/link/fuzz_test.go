package link

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParse checks that Parse never panics and that anything it accepts
// survives a build-and-parse round trip unchanged.
func FuzzParse(f *testing.F) {
	drop, _ := sampleDrop().Build(page)
	reveal, _ := sampleReveal().Build(page)
	seeds := []string{
		drop, reveal, page + "/drop#", page + "/drop#v=1", "", "#", "https://x/drop#v=1&i=&u=&k=&n=&t=",
		strings.Replace(drop, "&n=", "&n=%", 1), drop + "&r=https%3A%2F%2Frelay.example.com", reveal + "&r=http%3A%2F%2Flocalhost",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := Parse(raw)
		if err != nil {
			return
		}
		switch p.Kind {
		case KindDrop:
			rebuilt, err := p.Drop.Build(p.PageOrigin)
			if err != nil {
				t.Fatalf("accepted drop cannot be rebuilt: %v", err)
			}
			again, _, err := ParseDrop(rebuilt)
			if err != nil {
				t.Fatalf("rebuilt drop does not parse: %v", err)
			}
			if again.ID != p.Drop.ID || again.UploadToken != p.Drop.UploadToken || !bytes.Equal(again.RecipientKey, p.Drop.RecipientKey) ||
				again.Name != p.Drop.Name || again.Purpose != p.Drop.Purpose || again.Storage != p.Drop.Storage ||
				again.Retention != p.Drop.Retention || again.Relay != p.Drop.Relay {
				t.Fatalf("drop round trip changed fields: %+v vs %+v", again, *p.Drop)
			}
		case KindReveal:
			rebuilt, err := p.Reveal.Build(p.PageOrigin)
			if err != nil {
				t.Fatalf("accepted reveal cannot be rebuilt: %v", err)
			}
			again, _, err := ParseReveal(rebuilt)
			if err != nil {
				t.Fatalf("rebuilt reveal does not parse: %v", err)
			}
			if again.ID != p.Reveal.ID || again.RevealToken != p.Reveal.RevealToken || !bytes.Equal(again.Key, p.Reveal.Key) ||
				again.Name != p.Reveal.Name || again.KeepsCopy != p.Reveal.KeepsCopy || again.Relay != p.Reveal.Relay {
				t.Fatalf("reveal round trip changed fields")
			}
		default:
			t.Fatalf("unknown kind %q", p.Kind)
		}
	})
}
