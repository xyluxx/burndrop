// Package mcpserver exposes the agent flows as Model Context Protocol
// tools over the official Go SDK. No tool returns a secret value: outputs
// are names, identifiers, statuses, and messages, and every string that
// leaves a handler passes through the agent's redaction filter.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/burndrop/burndrop/internal/agent"
)

// ServerName is the MCP implementation name.
const ServerName = "burndrop"

// Options tune the server.
type Options struct {
	Version string
	// ConfirmSend asks the human through elicitation before send_secret
	// creates a link, when the client supports it. Default true.
	ConfirmSend *bool
}

// New builds the MCP server around an agent.
func New(a *agent.Agent, opts Options) *mcp.Server {
	if opts.Version == "" {
		opts.Version = "dev"
	}
	confirm := opts.ConfirmSend == nil || *opts.ConfirmSend
	s := mcp.NewServer(&mcp.Implementation{Name: ServerName, Title: "burndrop secret exchange", Version: opts.Version}, &mcp.ServerOptions{Instructions: Instructions})
	h := &handlers{agent: a, confirmSend: confirm}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "request_secret",
		Title:       "Request a secret from a human",
		Description: "Create a one-time link the human opens to submit a secret. The value is encrypted in their browser to a key only this agent holds and is stored by name; it is never returned to you. Relay the returned message verbatim.",
		Annotations: &mcp.ToolAnnotations{Title: "Request a secret", ReadOnlyHint: false, DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
	}, h.requestSecret)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "fetch_secret",
		Title:       "Fetch a submitted secret",
		Description: "Wait for the human to submit the secret for a request, then download, decrypt, verify, and store it. Returns the status and metadata, never the value. Call again while the status is waiting.",
		Annotations: &mcp.ToolAnnotations{Title: "Fetch a secret", DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
	}, h.fetchSecret)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "send_secret",
		Title:       "Send a secret to a human",
		Description: "Create a one-time link that reveals a stored secret to a human once. Only secrets marked sendable can be sent. The human may be asked to confirm first. Relay the returned message verbatim.",
		Annotations: &mcp.ToolAnnotations{Title: "Send a secret", DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)},
	}, h.sendSecret)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_with_secret",
		Title:       "Run a command with secrets",
		Description: "Run a program with stored secrets injected as environment variables. Output is returned with every known value redacted and truncated. With capture_as, the program's output is stored as a new sendable secret and not returned.",
		Annotations: &mcp.ToolAnnotations{Title: "Run with secrets", DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)},
	}, h.runWithSecret)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_secrets",
		Title:       "List stored secrets",
		Description: "List the names and metadata of stored secrets: where each is kept, its retention, when it was created and expires, whether it is sendable, and where it came from. Values are never included.",
		Annotations: &mcp.ToolAnnotations{Title: "List secrets", ReadOnlyHint: true, IdempotentHint: true, DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(false)},
	}, h.listSecrets)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_secret",
		Title:       "Delete a stored secret",
		Description: "Remove a stored secret by name from every place the agent keeps it.",
		Annotations: &mcp.ToolAnnotations{Title: "Delete a secret", DestructiveHint: boolPtr(true), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
	}, h.deleteSecret)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "revoke_request",
		Title:       "Revoke a pending request",
		Description: "Cancel a request whose link should no longer work, for example when the human reports a fingerprint mismatch. Returns the request's final state.",
		Annotations: &mcp.ToolAnnotations{Title: "Revoke a request", DestructiveHint: boolPtr(true), IdempotentHint: true, OpenWorldHint: boolPtr(true)},
	}, h.revokeRequest)

	return s
}

func boolPtr(b bool) *bool { return &b }

type handlers struct {
	agent       *agent.Agent
	confirmSend bool
}

// fail turns an error into a tool error with known values redacted.
func (h *handlers) fail(err error) error {
	return errors.New(h.agent.Redactor.Redact(err.Error()))
}

func (h *handlers) requestSecret(ctx context.Context, _ *mcp.CallToolRequest, in agent.RequestInput) (*mcp.CallToolResult, agent.RequestOutput, error) {
	out, err := h.agent.Request(ctx, in)
	if err != nil {
		return nil, agent.RequestOutput{}, h.fail(err)
	}
	return nil, out, nil
}

func (h *handlers) fetchSecret(ctx context.Context, _ *mcp.CallToolRequest, in agent.FetchInput) (*mcp.CallToolResult, agent.FetchOutput, error) {
	out, err := h.agent.Fetch(ctx, in)
	if err != nil {
		return nil, agent.FetchOutput{}, h.fail(err)
	}
	return nil, out, nil
}

// sendConfirmSchema is the flat form the client shows the human.
var sendConfirmSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"confirm": map[string]any{
			"type":        "boolean",
			"title":       "Create the one-time link",
			"description": "The agent wants to hand this secret to a person through a one-time link. Allow it?",
		},
	},
	"required": []string{"confirm"},
}

// confirmRequestID keys the elicitation inside the multi-round-trip result.
const confirmRequestID = "confirm"

func (h *handlers) sendSecret(ctx context.Context, req *mcp.CallToolRequest, in agent.SendInput) (*mcp.CallToolResult, agent.SendOutput, error) {
	if err := h.agent.CanSend(ctx, in.Name); err != nil {
		return nil, agent.SendOutput{}, h.fail(err)
	}
	if h.confirmSend && supportsElicitation(req) {
		// Elicitation during a tool call uses the multi round-trip pattern
		// (SEP-2322): the first call returns an input request, the client
		// shows it to the human, then calls again with the response. The SDK
		// performs the same exchange transparently for older clients.
		state := "send:" + in.Name
		resp, answered := req.Params.InputResponses[confirmRequestID]
		if !answered || req.Params.RequestState != state {
			return &mcp.CallToolResult{
				InputRequests: mcp.InputRequestMap{confirmRequestID: &mcp.ElicitParams{
					Mode:            "form",
					Message:         fmt.Sprintf("The agent wants to send the secret %q to a person through a one-time reveal link. Allow it?", in.Name),
					RequestedSchema: sendConfirmSchema,
				}},
				RequestState: state,
			}, agent.SendOutput{}, nil
		}
		er, ok := resp.(*mcp.ElicitResult)
		if !ok || er.Action != "accept" || !confirmed(er.Content) {
			h.agent.Audit.Log(agent.Event{Event: "send_secret", Name: in.Name, Result: "declined_by_human"})
			return nil, agent.SendOutput{}, errors.New("the human declined to send this secret")
		}
	}
	out, err := h.agent.Send(ctx, in)
	if err != nil {
		return nil, agent.SendOutput{}, h.fail(err)
	}
	return nil, out, nil
}

func supportsElicitation(req *mcp.CallToolRequest) bool {
	if req == nil || req.Session == nil {
		return false
	}
	params := req.Session.InitializeParams()
	return params != nil && params.Capabilities != nil && params.Capabilities.Elicitation != nil
}

func confirmed(content map[string]any) bool {
	v, ok := content["confirm"]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true") || strings.EqualFold(b, "yes")
	}
	return false
}

func (h *handlers) runWithSecret(ctx context.Context, _ *mcp.CallToolRequest, in agent.RunInput) (*mcp.CallToolResult, agent.RunOutput, error) {
	out, err := h.agent.Run(ctx, in)
	if err != nil {
		return nil, agent.RunOutput{}, h.fail(err)
	}
	return nil, out, nil
}

// ListInput has no fields; the SDK needs a struct for the schema.
type ListInput struct{}

// ListOutput wraps the entries so the output schema is an object.
type ListOutput struct {
	Secrets []SecretInfo `json:"secrets"`
}

// SecretInfo is one list_secrets entry.
type SecretInfo struct {
	Name      string `json:"name"`
	Storage   string `json:"storage"`
	Retention string `json:"retention"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Sendable  bool   `json:"sendable"`
	Source    string `json:"source"`
	Purpose   string `json:"purpose,omitempty"`
	SizeBytes int    `json:"size_bytes"`
}

func (h *handlers) listSecrets(ctx context.Context, _ *mcp.CallToolRequest, _ ListInput) (*mcp.CallToolResult, ListOutput, error) {
	list, err := h.agent.List(ctx)
	if err != nil {
		return nil, ListOutput{}, h.fail(err)
	}
	out := ListOutput{Secrets: make([]SecretInfo, 0, len(list))}
	for _, m := range list {
		info := SecretInfo{Name: m.Name, Storage: m.Backend, Retention: m.Retention, CreatedAt: m.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), Sendable: m.Sendable, Source: m.Source, Purpose: m.Purpose, SizeBytes: m.SizeBytes}
		if !m.ExpiresAt.IsZero() {
			info.ExpiresAt = m.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		out.Secrets = append(out.Secrets, info)
	}
	return nil, out, nil
}

// DeleteInput is the delete_secret input.
type DeleteInput struct {
	Name string `json:"name" jsonschema:"name of the stored secret"`
}

// DeleteOutput is the delete_secret output.
type DeleteOutput struct {
	Deleted bool   `json:"deleted"`
	Name    string `json:"name"`
}

func (h *handlers) deleteSecret(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, DeleteOutput, error) {
	if err := h.agent.Delete(ctx, in.Name); err != nil {
		return nil, DeleteOutput{}, h.fail(err)
	}
	return nil, DeleteOutput{Deleted: true, Name: in.Name}, nil
}

// RevokeInput is the revoke_request input.
type RevokeInput struct {
	RequestID string `json:"request_id" jsonschema:"the request_id returned by request_secret"`
}

// RevokeOutput is the revoke_request output.
type RevokeOutput struct {
	RequestID string `json:"request_id"`
	State     string `json:"state"`
}

func (h *handlers) revokeRequest(ctx context.Context, _ *mcp.CallToolRequest, in RevokeInput) (*mcp.CallToolResult, RevokeOutput, error) {
	state, err := h.agent.Revoke(ctx, in.RequestID)
	if err != nil {
		return nil, RevokeOutput{}, h.fail(err)
	}
	return nil, RevokeOutput{RequestID: in.RequestID, State: state}, nil
}
