package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/burndrop/burndrop/internal/client"
	"github.com/burndrop/burndrop/internal/crypto"
	"github.com/burndrop/burndrop/internal/link"
)

// cmdDrop is the human side of a request without a browser: it does exactly
// what the page does, with the same envelope and the same checks.
func (a *app) cmdDrop(ctx context.Context, args []string) error {
	fs := a.flags("drop", "LINK [-file PATH] [-yes]")
	file := fs.String("file", "", "read the secret from this file instead of the prompt or standard input")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	raw := fs.Arg(0)
	if raw == "" {
		fs.Usage()
		return errUsage
	}
	d, pageOrigin, err := link.ParseDrop(raw)
	if err != nil {
		return fmt.Errorf("this is not a valid drop link: %w", err)
	}
	relayOrigin := d.RelayOrigin(pageOrigin)
	fmt.Fprintf(a.stderr, "An agent is asking for a secret.\n  name:        %s\n  purpose:     %s\n  stored in:   %s\n  kept:        %s\n  fingerprint: %s\n  relay:       %s\n\nCompare the fingerprint with the one the agent showed you before continuing.\n", d.Name, d.Purpose, d.Storage, d.Retention, d.Fingerprint(), relayOrigin)
	rc, err := client.New(relayOrigin, "", "burndrop-cli/"+a.version)
	if err != nil {
		return err
	}
	st, err := rc.DropStatus(ctx, d.ID, 0, "")
	if err != nil {
		if client.IsCode(err, client.CodeNotFound) {
			return errors.New("this link has expired or was never created")
		}
		return err
	}
	if st.State != client.StateCreated {
		return fmt.Errorf("this link can no longer be used (state: %s)", st.State)
	}
	ok, err := a.confirm("Submit a secret for this request?", *yes)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("cancelled")
	}
	value, err := a.readValue(*file)
	if err != nil {
		return err
	}
	defer zero(value)
	if len(value) == 0 {
		return errors.New("empty value")
	}
	pub, err := crypto.KeyFromBytes(d.RecipientKey)
	if err != nil {
		return err
	}
	env := crypto.Envelope{V: 1, Type: crypto.TypeDrop, Name: d.Name, Purpose: d.Purpose, Storage: d.Storage, Retention: d.Retention, Fingerprint: d.Fingerprint()}
	env.SetSecret(value)
	sealed, err := crypto.SealEnvelope(pub, env, rand.Reader)
	if err != nil {
		return err
	}
	if err := rc.Upload(ctx, d.ID, d.UploadToken, crypto.Commitment(d.RecipientKey), sealed); err != nil {
		if client.IsCode(err, client.CodeCommitment) {
			return errors.New("the key in this link does not match the key the agent registered; the link was altered, do not use it")
		}
		return err
	}
	fmt.Fprintf(a.stdout, "submitted %s (%d bytes, encrypted to fingerprint %s); the link is now spent\n", d.Name, len(value), d.Fingerprint())
	return nil
}

// cmdOpen is the human side of a reveal without a browser.
func (a *app) cmdOpen(ctx context.Context, args []string) error {
	fs := a.flags("open", "LINK [-yes]")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	raw := fs.Arg(0)
	if raw == "" {
		fs.Usage()
		return errUsage
	}
	r, pageOrigin, err := link.ParseReveal(raw)
	if err != nil {
		return fmt.Errorf("this is not a valid reveal link: %w", err)
	}
	relayOrigin := r.RelayOrigin(pageOrigin)
	keeps := "the agent keeps its own copy"
	if !r.KeepsCopy {
		keeps = "the agent has deleted its copy"
	}
	fmt.Fprintf(a.stderr, "An agent is sharing a secret with you.\n  name:  %s\n  note:  %s\n  relay: %s\n\nOpening it deletes it from the relay; it can be shown only once.\n", r.Name, keeps, relayOrigin)
	rc, err := client.New(relayOrigin, "", "burndrop-cli/"+a.version)
	if err != nil {
		return err
	}
	st, err := rc.RevealStatus(ctx, r.ID, 0, "")
	if err != nil {
		if client.IsCode(err, client.CodeNotFound) {
			return errors.New("this link has expired or was never created")
		}
		return err
	}
	if st.State != client.StateCreated {
		return fmt.Errorf("this link was already used or revoked (state: %s)", st.State)
	}
	ok, err := a.confirm("Reveal it now?", *yes)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("cancelled; the secret is still on the relay until " + st.ExpiresAt.UTC().Format(time.RFC3339))
	}
	ct, _, err := rc.Open(ctx, r.ID, r.RevealToken)
	if err != nil {
		return err
	}
	key, err := crypto.KeyFromBytes(r.Key)
	if err != nil {
		return err
	}
	defer crypto.ZeroKey(key)
	env, err := crypto.DecryptEnvelope(key, ct, r.AAD())
	if err != nil {
		return errors.New("the secret could not be decrypted: the link was altered or the relay returned the wrong data; the relay copy is gone, ask the agent to send it again")
	}
	value, err := env.SecretBytes()
	if err != nil {
		return err
	}
	defer zero(value)
	if _, err := a.stdout.Write(value); err != nil {
		return err
	}
	if len(value) > 0 && value[len(value)-1] != '\n' {
		fmt.Fprintln(a.stdout)
	}
	fmt.Fprintln(a.stderr, "(the relay copy is deleted; store the value somewhere safe)")
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
