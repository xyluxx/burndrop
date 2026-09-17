package crypto

import (
	"bytes"
	"testing"
)

// FuzzDecodeEnvelope checks that the envelope decoder never panics and that
// whatever it accepts survives an encode and decode round trip unchanged.
func FuzzDecodeEnvelope(f *testing.F) {
	for _, s := range []string{
		`{"v":1,"type":"drop","name":"openai-api-key","purpose":"p","storage":"s","retention":"until-revoked","fingerprint":"a1b2-c3d4-e5f6-a7b8","format":"text","secret":"sk-live"}`,
		`{"v":1,"type":"reveal","name":"staging-db-url","format":"base64","secret":"AAEC"}`,
		`{"v":2,"type":"drop","name":"a","format":"text","secret":"x"}`,
		`{"v":1,"type":"drop","name":"a","format":"text","secret":"x","extra":1}`,
		`{"v":1,"type":"drop","name":"a","format":"text","secret":" "}`,
		`{`, ``, `[]`, `"x"`, `null`, `{"v":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		env, err := DecodeEnvelope(b)
		if err != nil {
			return
		}
		enc, err := env.Encode()
		if err != nil {
			t.Fatalf("accepted envelope does not encode: %v", err)
		}
		again, err := DecodeEnvelope(enc)
		if err != nil {
			t.Fatalf("encoded envelope does not decode: %v", err)
		}
		if again != env {
			t.Fatalf("round trip changed the envelope")
		}
	})
}

// FuzzPadding checks that padding round-trips and that unpadding arbitrary
// input never panics.
func FuzzPadding(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("x"))
	f.Add(bytes.Repeat([]byte{0x80}, 255))
	f.Add(bytes.Repeat([]byte{0}, 256))
	f.Add([]byte{0x80})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			return
		}
		out, err := Unpad(Pad(b, 256), 256)
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("pad round trip failed: %v", err)
		}
		_, _ = Unpad(b, 256)
	})
}
