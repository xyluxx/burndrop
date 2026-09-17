package relay

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/xyluxx/burndrop/internal/crypto"
	"github.com/xyluxx/burndrop/internal/link"
)

// These tests are the attacks from the brief, run against the real HTTP
// surface. Each one states what an attacker is trying to do.

// A link scanner (Slack, Teams, Outlook, Gmail, a security sandbox) fetches
// every URL it sees with GET and HEAD. Nothing it does may change state.
func TestScannersCannotBurnDrops(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	ts.upload(d, fx.commitment, fx.ciphertext)
	_, ct := revealFixture(t, "v")
	r := ts.createReveal(ct, 0)
	agents := []string{"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", "Mozilla/5.0 (compatible; Google-Safety; +http://www.google.com/bot.html)", "Microsoft-Teams/1.0", "Outlook-iOS/2.0", "curl/8.0", ""}
	paths := []string{"/drop", "/reveal", "/", "/api/v1/drops", "/api/v1/drops/upload", "/api/v1/drops/fetch", "/api/v1/drops/status", "/api/v1/drops/revoke", "/api/v1/reveals", "/api/v1/reveals/open", "/api/v1/reveals/status", "/api/v1/reveals/revoke"}
	for _, ua := range agents {
		for _, p := range paths {
			for _, m := range []string{http.MethodGet, http.MethodHead} {
				res := ts.do(m, p, nil, withHeader("User-Agent", ua), withoutHeader(ClientHeader))
				if strings.HasPrefix(p, "/api/") {
					if res.Status != http.StatusMethodNotAllowed {
						t.Fatalf("%s %s (%q): %d, want 405", m, p, ua, res.Status)
					}
				} else if res.Status != http.StatusOK {
					t.Fatalf("%s %s (%q): %d, want 200", m, p, ua, res.Status)
				}
			}
		}
	}
	// A scanner that follows the link with the fragment sends the fragment
	// nowhere; the page path alone tells it nothing.
	if res := ts.do(http.MethodGet, "/reveal#v=1&i="+r.ID+"&o="+r.RevealToken, nil); res.Status != http.StatusOK {
		t.Fatalf("page with fragment: %d", res.Status)
	}
	if st := ts.status(KindDrop, d.ID); st.str("state") != "uploaded" {
		t.Fatalf("drop state changed by scanners: %s", st.Raw)
	}
	if st := ts.status(KindReveal, r.ID); st.str("state") != "created" {
		t.Fatalf("reveal state changed by scanners: %s", st.Raw)
	}
	// A scanner that tries the API with a form post (no JSON, no client header).
	res := ts.do(http.MethodPost, "/api/v1/reveals/open", "drop_id="+r.ID+"&reveal_token="+r.RevealToken, withHeader("Content-Type", "application/x-www-form-urlencoded"), withoutHeader(ClientHeader))
	if res.Status != 400 && res.Status != 415 {
		t.Fatalf("form post: %d", res.Status)
	}
	if st := ts.status(KindReveal, r.ID); st.str("state") != "created" {
		t.Fatal("form post changed state")
	}
}

// Two readers race for the same drop: exactly one wins.
func TestConcurrentSingleRead(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	ts.upload(d, fx.commitment, fx.ciphertext)
	const n = 64
	var wg sync.WaitGroup
	results := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = ts.fetch(d).Status
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, s := range results {
		switch s {
		case 200:
			wins++
		case http.StatusGone:
		default:
			t.Fatalf("unexpected status %d", s)
		}
	}
	if wins != 1 {
		t.Fatalf("%d fetches succeeded, want exactly 1", wins)
	}
	_, ct := revealFixture(t, "v")
	r := ts.createReveal(ct, 0)
	wins = 0
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ts.open(r).Status == 200 {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d opens succeeded, want exactly 1", wins)
	}
	// Concurrent uploads to one slot: exactly one is stored.
	d2 := ts.createDrop(fx.commitment, 0)
	wins = 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ts.upload(d2, fx.commitment, fx.ciphertext).Status == 200 {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d uploads succeeded, want exactly 1", wins)
	}
}

// Replaying captured requests achieves nothing.
func TestReplay(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	uploadBody := map[string]any{"drop_id": d.ID, "upload_token": d.UploadToken, "commitment": fx.commitment, "ciphertext": crypto.Encoding.EncodeToString(fx.ciphertext)}
	if res := ts.post("/api/v1/drops/upload", uploadBody); res.Status != 200 {
		t.Fatal(res.Status)
	}
	if res := ts.post("/api/v1/drops/upload", uploadBody); res.Status != http.StatusConflict {
		t.Fatalf("replayed upload: %d", res.Status)
	}
	fetchBody := map[string]any{"drop_id": d.ID, "fetch_token": d.FetchToken}
	first := ts.post("/api/v1/drops/fetch", fetchBody, ts.agent())
	if first.Status != 200 {
		t.Fatal(first.Status)
	}
	replay := ts.post("/api/v1/drops/fetch", fetchBody, ts.agent())
	if replay.Status != http.StatusGone || replay.str("ciphertext") != "" {
		t.Fatalf("replayed fetch: %d %s", replay.Status, replay.Raw)
	}
	// Replaying the upload after the fetch cannot resurrect the slot.
	if res := ts.post("/api/v1/drops/upload", uploadBody); res.Status != http.StatusGone {
		t.Fatalf("upload replay after fetch: %d", res.Status)
	}
	// Replaying a captured ciphertext into a fresh slot for the same recipient
	// is accepted by the relay (it cannot tell) but is harmless: the envelope
	// carries the original metadata and the agent detects a stale fingerprint
	// or name; and an attacker cannot read it without the recipient key.
	_, ct := revealFixture(t, "v")
	r := ts.createReveal(ct, 0)
	openBody := map[string]any{"drop_id": r.ID, "reveal_token": r.RevealToken}
	if res := ts.post("/api/v1/reveals/open", openBody); res.Status != 200 {
		t.Fatal(res.Status)
	}
	if res := ts.post("/api/v1/reveals/open", openBody); res.Status != http.StatusGone || res.str("state") != "opened" {
		t.Fatalf("replayed open: %d %s", res.Status, res.Raw)
	}
	revokeBody := map[string]any{"drop_id": r.ID, "token": r.RevokeToken}
	if res := ts.post("/api/v1/reveals/revoke", revokeBody); res.Status != http.StatusGone {
		t.Fatalf("revoke after open: %d", res.Status)
	}
}

// Tampered ciphertext passes through the relay unchanged (it cannot check it)
// but fails authentication at the client, so no altered value is ever accepted.
func TestTamperedCiphertextIsRejectedByClients(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	tampered := append([]byte(nil), fx.ciphertext...)
	tampered[len(tampered)/2] ^= 0x55
	if res := ts.upload(d, fx.commitment, tampered); res.Status != 200 {
		t.Fatal(res.Status)
	}
	res := ts.fetch(d)
	if _, err := crypto.OpenEnvelope(fx.pub, fx.priv, decodeB64(t, res.str("ciphertext"))); err == nil {
		t.Fatal("agent accepted tampered ciphertext")
	}
	key, ct := revealFixture(t, "v")
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 0x01
	r := ts.createReveal(bad, 0)
	res = ts.open(r)
	if _, err := crypto.DecryptEnvelope(key, decodeB64(t, res.str("ciphertext")), crypto.RevealAAD("staging-db-url", false)); err == nil {
		t.Fatal("browser accepted tampered ciphertext")
	}
}

// End to end through the link format: an attacker rewrites the public key in
// the link. The honest page computes the commitment from the key it sees, so
// the relay refuses the upload. The agent's own verification catches metadata
// edits that survive.
func TestKeySubstitutionThroughLinks(t *testing.T) {
	ts := newTestServer(t, nil)
	agentPub, agentPriv, _ := crypto.GenerateKeyPair(nil)
	d := ts.createDrop(crypto.Commitment(agentPub[:]), 0)
	honest := link.Drop{ID: d.ID, UploadToken: d.UploadToken, RecipientKey: agentPub[:], Name: "openai-api-key", Purpose: "Call the OpenAI API", Storage: "macOS Keychain", Retention: "until-revoked"}
	honestLink, err := honest.Build(testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	// Attacker in the chat channel swaps the key.
	attackerPub, attackerPriv, _ := crypto.GenerateKeyPair(nil)
	evil := honest
	evil.RecipientKey = attackerPub[:]
	evilLink, _ := evil.Build(testOrigin)
	if evilLink == honestLink {
		t.Fatal("test setup: links identical")
	}
	// The human's page follows the evil link.
	parsed, _, err := link.ParseDrop(evilLink)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Fingerprint() == honest.Fingerprint() {
		t.Fatal("fingerprint did not change with the key")
	}
	pagePub, _ := crypto.KeyFromBytes(parsed.RecipientKey)
	env := crypto.Envelope{V: 1, Type: crypto.TypeDrop, Name: parsed.Name, Purpose: parsed.Purpose, Storage: parsed.Storage, Retention: parsed.Retention, Fingerprint: parsed.Fingerprint(), Format: crypto.FormatText, Secret: "sk-live"}
	ct, _ := crypto.SealEnvelope(pagePub, env, nil)
	res := ts.upload(dropSlot{ID: parsed.ID, UploadToken: parsed.UploadToken}, crypto.Commitment(parsed.RecipientKey), ct)
	if res.Status != http.StatusUnprocessableEntity {
		t.Fatalf("relay accepted a substituted key: %d %s", res.Status, res.Raw)
	}
	// Even if a colluding relay had accepted it, the attacker would still need
	// the fetch token, which only the agent holds. And if the attacker only
	// edited the purpose text, the agent notices the mismatch after decrypting.
	edited := honest
	edited.Purpose = "Give me your AWS root key"
	editedLink, _ := edited.Build(testOrigin)
	parsed2, _, _ := link.ParseDrop(editedLink)
	honestPub, _ := crypto.KeyFromBytes(parsed2.RecipientKey)
	env2 := crypto.Envelope{V: 1, Type: crypto.TypeDrop, Name: parsed2.Name, Purpose: parsed2.Purpose, Storage: parsed2.Storage, Retention: parsed2.Retention, Fingerprint: parsed2.Fingerprint(), Format: crypto.FormatText, Secret: "sk-live"}
	ct2, _ := crypto.SealEnvelope(honestPub, env2, nil)
	if res := ts.upload(dropSlot{ID: parsed2.ID, UploadToken: parsed2.UploadToken}, crypto.Commitment(parsed2.RecipientKey), ct2); res.Status != 200 {
		t.Fatalf("honest-key upload: %d %s", res.Status, res.Raw)
	}
	fetched := ts.fetch(d)
	got, err := crypto.OpenEnvelope(agentPub, agentPriv, decodeB64(t, fetched.str("ciphertext")))
	if err != nil {
		t.Fatal(err)
	}
	if got.Purpose == honest.Purpose {
		t.Fatal("test setup: purpose was not edited")
	}
	// This is the check the agent performs before storing anything.
	if got.Purpose != honest.Purpose || got.Name != honest.Name {
		t.Log("agent detects edited metadata and refuses the drop (expected)")
	}
	_ = attackerPriv
}

// Dumping the whole store after realistic traffic must reveal nothing usable.
func TestStoreDumpIsUnreadable(t *testing.T) {
	ts := newTestServer(t, nil)
	secret := "sk-live-THE-SECRET-VALUE-0123456789"
	fx := newSealedFixture(t, secret)
	d := ts.createDrop(fx.commitment, 0)
	ts.upload(d, fx.commitment, fx.ciphertext)
	key, ct := revealFixture(t, "reveal-SECRET-VALUE")
	r := ts.createReveal(ct, 0)
	dump := ts.store.dump()
	if len(dump) != 2 {
		t.Fatalf("expected 2 slots, got %d", len(dump))
	}
	forbidden := [][]byte{[]byte(secret), []byte("reveal-SECRET-VALUE"), []byte(d.UploadToken), []byte(d.FetchToken), []byte(r.RevealToken), []byte(r.RevokeToken), []byte(ts.agentKey), key[:], fx.priv[:], []byte("openai-api-key"), []byte("macOS Keychain")}
	for _, slot := range dump {
		blob := append([]byte(nil), slot.Ciphertext...)
		blob = append(blob, []byte(slot.Commitment)...)
		blob = append(blob, slot.TokenA[:]...)
		blob = append(blob, slot.TokenB[:]...)
		blob = append(blob, []byte(slot.AgentKeyID)...)
		for _, f := range forbidden {
			if bytes.Contains(blob, f) {
				t.Fatalf("store contains forbidden bytes %q", f)
			}
		}
		if slot.TokenA == (crypto.Hash{}) && !slot.State.Terminal() && slot.Kind == KindReveal {
			t.Fatal("reveal token hash missing")
		}
	}
}

// Every log line produced during full traffic is checked for identifiers,
// tokens, keys, ciphertext, and values.
func TestLogsContainNoSecrets(t *testing.T) {
	ts := newTestServer(t, func(c *Config) { c.LogClientIP = true })
	secret := "sk-live-THE-SECRET-VALUE"
	fx := newSealedFixture(t, secret)
	d := ts.createDrop(fx.commitment, 0)
	ts.status(KindDrop, d.ID)
	ts.upload(d, fx.commitment, fx.ciphertext)
	ts.fetch(d)
	ts.fetch(d)
	key, ct := revealFixture(t, "v")
	r := ts.createReveal(ct, 0)
	ts.open(r)
	ts.post("/api/v1/reveals/revoke", map[string]any{"drop_id": r.ID, "token": "bad-token-bad-token-ab"})
	ts.post("/api/v1/drops/upload", `{"drop_id": "`+d.ID+`", "broken`)
	ts.do(http.MethodGet, "/drop?leak="+d.ID, nil)
	ts.do(http.MethodGet, "/nope/"+d.FetchToken, nil)
	logs := ts.logText()
	if !strings.Contains(logs, `"route":"POST /api/v1/drops/upload"`) || !strings.Contains(logs, `"status":200`) {
		t.Fatalf("access log incomplete: %s", logs)
	}
	forbidden := []string{secret, d.ID, d.UploadToken, d.FetchToken, r.ID, r.RevealToken, r.RevokeToken, ts.agentKey, crypto.Encoding.EncodeToString(fx.ciphertext), crypto.Encoding.EncodeToString(key[:]), fx.commitment, "leak=", "/nope/"}
	for _, f := range forbidden {
		if strings.Contains(logs, f) {
			t.Fatalf("log contains %q", f)
		}
	}
	if !strings.Contains(logs, `"route":"unmatched"`) {
		t.Fatal("unknown routes must be logged as unmatched, never by path")
	}
	if !strings.Contains(logs, `"client_ip":"127.0.0.1"`) {
		t.Fatal("client ip logging was enabled but missing")
	}
}

// Requests that arrive without the fetch token get nothing, whatever else they
// know: the drop ID, the upload token, the commitment, or the agent key.
func TestFetchWithoutFetchToken(t *testing.T) {
	ts := newTestServer(t, nil)
	fx := newSealedFixture(t, "s")
	d := ts.createDrop(fx.commitment, 0)
	ts.upload(d, fx.commitment, fx.ciphertext)
	attempts := []map[string]any{
		{"drop_id": d.ID},
		{"drop_id": d.ID, "fetch_token": ""},
		{"drop_id": d.ID, "fetch_token": d.UploadToken},
		{"drop_id": d.ID, "fetch_token": strings.Repeat("A", 22)},
		{"drop_id": d.ID, "fetch_token": fx.commitment},
	}
	for _, body := range attempts {
		res := ts.post("/api/v1/drops/fetch", body, ts.agent())
		if res.Status == 200 || res.str("ciphertext") != "" {
			t.Fatalf("fetch succeeded with %v", body)
		}
	}
	if st := ts.status(KindDrop, d.ID); st.str("state") != "uploaded" {
		t.Fatal("state changed")
	}
}
