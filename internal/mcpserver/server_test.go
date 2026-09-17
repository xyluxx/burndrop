package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xyluxx/burndrop/internal/agent"
	"github.com/xyluxx/burndrop/internal/client"
	"github.com/xyluxx/burndrop/internal/crypto"
	"github.com/xyluxx/burndrop/internal/link"
	"github.com/xyluxx/burndrop/internal/relay"
	"github.com/xyluxx/burndrop/internal/storage"
)

const testKey = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

type fixture struct {
	agent    *agent.Agent
	relay    *client.Client
	session  *mcp.ClientSession
	elicited []string
	answer   func() *mcp.ElicitResult
	results  []string
}

func newFixture(t *testing.T, withElicitation bool) *fixture {
	t.Helper()
	cfg := relay.DefaultConfig()
	cfg.PublicOrigin = "http://127.0.0.1"
	cfg.AgentKeys = []relay.AgentKey{{ID: "test", Hash: crypto.HashToken(testKey)}}
	cfg.RateAgentPerMin = 10000
	cfg.RatePagePerMin = 10000
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := relay.NewStore(cfg, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(relay.New(cfg, store, relay.Options{Version: "test"}).Handler())
	t.Cleanup(srv.Close)
	rc, err := client.New(srv.URL, testKey, "burndrop-test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	idx, _ := storage.OpenIndex(filepath.Join(dir, "index.json"))
	manager := storage.NewManager(storage.NewMemory(), idx, nil)
	audit, _ := agent.NewAudit(filepath.Join(dir, "audit.log"), nil)
	acfg := agent.Config{Relay: srv.URL, Storage: "memory"}
	a := agent.New(acfg, rc, manager, audit)
	f := &fixture{agent: a, relay: rc}
	f.answer = func() *mcp.ElicitResult {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"confirm": true}}
	}

	server := New(a, Options{Version: "test"})
	st, ct := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx, st) }()
	copts := &mcp.ClientOptions{}
	if withElicitation {
		copts.ElicitationHandler = func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			f.elicited = append(f.elicited, req.Params.Message)
			return f.answer(), nil
		}
	}
	cl := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, copts)
	session, err := cl.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	f.session = session
	return f
}

// call invokes a tool and records the raw result text for leak checks.
func (f *fixture) call(t *testing.T, name string, args map[string]any) (*mcp.CallToolResult, map[string]any) {
	t.Helper()
	res, err := f.session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	raw, _ := json.Marshal(res)
	f.results = append(f.results, string(raw))
	var out map[string]any
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(b, &out)
	}
	return res, out
}

func (f *fixture) submit(t *testing.T, url, value string) {
	t.Helper()
	d, _, err := link.ParseDrop(url)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := crypto.KeyFromBytes(d.RecipientKey)
	env := crypto.Envelope{V: 1, Type: crypto.TypeDrop, Name: d.Name, Purpose: d.Purpose, Storage: d.Storage, Retention: d.Retention, Fingerprint: d.Fingerprint(), Format: crypto.FormatText, Secret: value}
	sealed, err := crypto.SealEnvelope(pub, env, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.relay.Upload(context.Background(), d.ID, d.UploadToken, crypto.Commitment(d.RecipientKey), sealed); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) assertNoLeak(t *testing.T, secrets ...string) {
	t.Helper()
	for _, r := range f.results {
		for _, s := range secrets {
			if strings.Contains(r, s) {
				t.Fatalf("secret value leaked into a tool result: %s", r)
			}
		}
	}
}

func errText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestToolList(t *testing.T) {
	f := newFixture(t, true)
	res, err := f.session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"request_secret": false, "fetch_secret": false, "send_secret": true, "run_with_secret": true, "list_secrets": false, "delete_secret": true, "revoke_request": true, "reveal_password": false}
	if len(res.Tools) != len(want) {
		t.Fatalf("got %d tools", len(res.Tools))
	}
	for _, tool := range res.Tools {
		destructive, ok := want[tool.Name]
		if !ok {
			t.Fatalf("unexpected tool %s", tool.Name)
		}
		if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint != destructive {
			t.Fatalf("%s: destructive hint wrong: %+v", tool.Name, tool.Annotations)
		}
		if tool.Description == "" || tool.InputSchema == nil {
			t.Fatalf("%s: missing description or schema", tool.Name)
		}
		if tool.Name == "list_secrets" && !tool.Annotations.ReadOnlyHint {
			t.Fatal("list_secrets must be read only")
		}
		schema, _ := json.Marshal(tool.InputSchema)
		if strings.Contains(strings.ToLower(string(schema)), `"value"`) {
			t.Fatalf("%s: schema mentions a value field: %s", tool.Name, schema)
		}
	}
	if params := f.session.InitializeResult(); params == nil || !strings.Contains(params.Instructions, "Never ask a human to paste a secret") || !strings.Contains(params.Instructions, "only to the human you are working for") {
		t.Fatal("instructions not sent")
	}
}

func TestFullFlow(t *testing.T) {
	f := newFixture(t, true)
	const secret = "sk-live-0123456789abcdef"

	// request_secret
	res, out := f.call(t, "request_secret", map[string]any{"name": "openai-api-key", "purpose": "Call the OpenAI API for the nightly report", "ttl": "30m"})
	if res.IsError {
		t.Fatalf("request: %s", errText(res))
	}
	reqID, _ := out["request_id"].(string)
	url, _ := out["link"].(string)
	msg, _ := out["message"].(string)
	if reqID == "" || !strings.Contains(url, "/drop#") || !strings.Contains(msg, url) || !strings.Contains(msg, out["fingerprint"].(string)) {
		t.Fatalf("request output: %+v", out)
	}
	if note, _ := out["delivery"].(string); !strings.Contains(note, "only to the human you are working for") {
		t.Fatalf("delivery note: %+v", out)
	}
	// Validation errors are tool errors, not protocol errors.
	res, _ = f.call(t, "request_secret", map[string]any{"name": "bad name!", "purpose": "p"})
	if !res.IsError || !strings.Contains(errText(res), "name") {
		t.Fatalf("validation: %+v", res)
	}
	// fetch_secret while waiting
	res, out = f.call(t, "fetch_secret", map[string]any{"request_id": reqID, "wait_seconds": 1})
	if res.IsError || out["status"] != "waiting" {
		t.Fatalf("waiting: %s %+v", errText(res), out)
	}
	f.submit(t, url, secret)
	res, out = f.call(t, "fetch_secret", map[string]any{"request_id": reqID})
	if res.IsError || out["status"] != "stored" || out["name"] != "openai-api-key" || out["storage"] != "memory" {
		t.Fatalf("stored: %s %+v", errText(res), out)
	}
	// list_secrets
	res, out = f.call(t, "list_secrets", map[string]any{})
	list, _ := out["secrets"].([]any)
	if res.IsError || len(list) != 1 {
		t.Fatalf("list: %s %+v", errText(res), out)
	}
	entry := list[0].(map[string]any)
	if entry["name"] != "openai-api-key" || entry["sendable"] != false || entry["source"] != "drop" || entry["storage"] != "memory" {
		t.Fatalf("entry: %+v", entry)
	}
	// run_with_secret redacts
	sh, args := shellFor(t)
	echo := "echo key=$OPENAI_API_KEY"
	if sh == "cmd" {
		echo = "echo key=%OPENAI_API_KEY%"
	}
	res, out = f.call(t, "run_with_secret", map[string]any{"command": append([]any{sh, args}, echo), "env": map[string]any{"OPENAI_API_KEY": "openai-api-key"}})
	if res.IsError || out["exit_code"] != float64(0) || !strings.Contains(out["stdout"].(string), "key=[redacted:openai-api-key]") {
		t.Fatalf("run: %s %+v", errText(res), out)
	}
	// send_secret refuses a non-sendable secret without asking the human.
	f.elicited = nil
	res, _ = f.call(t, "send_secret", map[string]any{"name": "openai-api-key"})
	if !res.IsError || !strings.Contains(errText(res), "not marked sendable") {
		t.Fatalf("send non-sendable: %s", errText(res))
	}
	if len(f.elicited) != 0 {
		t.Fatal("the human must not be asked to confirm a send that is refused anyway")
	}
	// Capture a generated value, then send it with confirmation.
	res, out = f.call(t, "run_with_secret", map[string]any{"command": append([]any{sh, args}, "echo generated-token-xyz789"), "capture_as": map[string]any{"name": "new-token", "purpose": "made by run"}})
	if res.IsError || out["stored_as"] != "new-token" || out["stdout"] != nil {
		t.Fatalf("capture: %s %+v", errText(res), out)
	}
	f.elicited = nil
	res, out = f.call(t, "send_secret", map[string]any{"name": "new-token", "ttl": "20m"})
	if res.IsError {
		t.Fatalf("send: %s", errText(res))
	}
	if len(f.elicited) != 1 || !strings.Contains(f.elicited[0], "new-token") {
		t.Fatalf("elicitation not used: %v", f.elicited)
	}
	revealURL, _ := out["link"].(string)
	if !strings.Contains(revealURL, "/reveal#") || out["keeps_copy"] != true {
		t.Fatalf("send output: %+v", out)
	}
	// The human opens it and gets the generated value.
	rv, _, err := link.ParseReveal(revealURL)
	if err != nil {
		t.Fatal(err)
	}
	ct, _, err := f.relay.Open(context.Background(), rv.ID, rv.RevealToken)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.KeyFromBytes(rv.Key)
	env, err := crypto.DecryptEnvelope(key, ct, rv.AAD())
	if err != nil || env.Secret != "generated-token-xyz789" {
		t.Fatalf("open: %v %+v", err, env)
	}
	// Declined confirmation creates nothing.
	f.answer = func() *mcp.ElicitResult { return &mcp.ElicitResult{Action: "decline"} }
	res, _ = f.call(t, "send_secret", map[string]any{"name": "new-token"})
	if !res.IsError || !strings.Contains(errText(res), "declined") {
		t.Fatalf("declined: %+v", res)
	}
	f.answer = func() *mcp.ElicitResult {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"confirm": false}}
	}
	if res, _ := f.call(t, "send_secret", map[string]any{"name": "new-token"}); !res.IsError {
		t.Fatal("confirm=false must refuse")
	}
	f.answer = func() *mcp.ElicitResult { return &mcp.ElicitResult{Action: "cancel"} }
	if res, _ := f.call(t, "send_secret", map[string]any{"name": "new-token"}); !res.IsError {
		t.Fatal("cancel must refuse")
	}
	f.answer = func() *mcp.ElicitResult {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"confirm": true}}
	}
	if res, _ := f.call(t, "send_secret", map[string]any{"name": "new-token"}); res.IsError {
		t.Fatalf("accepted again: %s", errText(res))
	}
	// delete_secret and revoke_request
	res, out = f.call(t, "delete_secret", map[string]any{"name": "new-token"})
	if res.IsError || out["deleted"] != true {
		t.Fatalf("delete: %s %+v", errText(res), out)
	}
	if res, _ := f.call(t, "delete_secret", map[string]any{"name": "new-token"}); !res.IsError {
		t.Fatal("double delete must be an error")
	}
	res, out = f.call(t, "request_secret", map[string]any{"name": "temp", "purpose": "p"})
	if res.IsError {
		t.Fatal(errText(res))
	}
	res, out = f.call(t, "revoke_request", map[string]any{"request_id": out["request_id"]})
	if res.IsError || out["state"] != "revoked" {
		t.Fatalf("revoke: %s %+v", errText(res), out)
	}
	if res, _ := f.call(t, "revoke_request", map[string]any{"request_id": "MTIzNDU2Nzg5MGFiY2RlZg"}); !res.IsError {
		t.Fatal("unknown request must be an error")
	}
	// Nothing that went through the tools ever carried a value.
	f.assertNoLeak(t, secret, "generated-token-xyz789", "c2stbGl2ZS0wMTIzNDU2Nzg5YWJjZGVm")
}

func TestSendWithoutElicitation(t *testing.T) {
	f := newFixture(t, false)
	if _, err := f.agent.Store.Put(context.Background(), "gen", []byte("generated-value-1"), storage.Metadata{Retention: storage.RetentionSession, Sendable: true}); err != nil {
		t.Fatal(err)
	}
	res, out := f.call(t, "send_secret", map[string]any{"name": "gen"})
	if res.IsError || !strings.Contains(out["link"].(string), "/reveal#") {
		t.Fatalf("send without elicitation: %s %+v", errText(res), out)
	}
	f.assertNoLeak(t, "generated-value-1")
	if note, _ := out["delivery"].(string); !strings.Contains(note, "only to the human you are working for") {
		t.Fatalf("delivery note: %+v", out)
	}
	// A sent link can be revoked with its request_id until it is opened.
	res, out = f.call(t, "revoke_request", map[string]any{"request_id": out["request_id"]})
	if res.IsError || out["state"] != "revoked" {
		t.Fatalf("revoke sent link: %s %+v", errText(res), out)
	}
	// Disabled confirmation skips elicitation even when supported.
	off := false
	s := New(f.agent, Options{ConfirmSend: &off})
	if s == nil {
		t.Fatal("server")
	}
	if confirmed(map[string]any{}) || confirmed(map[string]any{"confirm": 1}) || !confirmed(map[string]any{"confirm": "TRUE"}) {
		t.Fatal("confirmed parsing")
	}
	if supportsElicitation(nil) || supportsElicitation(&mcp.CallToolRequest{}) {
		t.Fatal("nil session must not support elicitation")
	}
}

func shellFor(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err == nil {
		return "sh", "-c"
	}
	if _, err := exec.LookPath("cmd"); err == nil {
		return "cmd", "/c"
	}
	t.Skip("no shell")
	return "", ""
}

func TestRevealPasswordTool(t *testing.T) {
	f := newFixture(t, false)
	// Nothing set: the report says so and turning it on fails.
	_, out := f.call(t, "reveal_password", nil)
	if out["required"] != false || out["configured"] != false || !strings.Contains(out["message"].(string), "reveal-password set") {
		t.Fatalf("status: %v", out)
	}
	res, _ := f.call(t, "reveal_password", map[string]any{"required": true})
	if !res.IsError || !strings.Contains(errText(res), "reveal-password set") {
		t.Fatalf("enable without a password: %+v", res)
	}
	if f.agent.Config.RevealPasswordRequired {
		t.Fatal("requirement turned on without a password")
	}

	// The human set one in a terminal: the agent can toggle the requirement
	// and send_secret links carry a salt while it is on.
	f.agent.Config.RevealPassword = "env:BURNDROP_TEST_PW"
	f.agent.PasswordSource = func() ([]byte, error) { return []byte("correct horse battery staple"), nil }
	_, out = f.call(t, "reveal_password", map[string]any{"required": true})
	if out["required"] != true || out["configured"] != true {
		t.Fatalf("enable: %v", out)
	}
	if _, err := f.agent.Store.Put(context.Background(), "gen", []byte("tok-1"), storage.Metadata{Retention: storage.RetentionSession, Sendable: true}); err != nil {
		t.Fatal(err)
	}
	res, sent := f.call(t, "send_secret", map[string]any{"name": "gen"})
	if res.IsError {
		t.Fatalf("send with password: %s", errText(res))
	}
	if sent["password_protected"] != true || !strings.Contains(sent["link"].(string), "&s=") || !strings.Contains(sent["message"].(string), "reveal password") {
		t.Fatalf("send with password: %v", sent)
	}
	_, out = f.call(t, "reveal_password", map[string]any{"required": false})
	if out["required"] != false || out["configured"] != true || !strings.Contains(out["message"].(string), "not required") {
		t.Fatalf("disable: %v", out)
	}
	_, sent = f.call(t, "send_secret", map[string]any{"name": "gen"})
	if sent["password_protected"] != false || strings.Contains(sent["link"].(string), "&s=") {
		t.Fatalf("send without password: %v", sent)
	}
	for _, raw := range f.results {
		if strings.Contains(raw, "correct horse") || strings.Contains(raw, "tok-1") {
			t.Fatal("a password or value leaked into a tool result")
		}
	}
}
