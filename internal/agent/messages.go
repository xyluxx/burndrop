package agent

import (
	"fmt"
	"strings"
	"time"
)

// describeStorage turns a backend name into words for the human.
func describeStorage(backend string) string {
	switch backend {
	case "keychain":
		return "the OS keychain on the agent's machine"
	case "agevault":
		return "an encrypted vault file on the agent's machine"
	case "memory":
		return "the agent's process memory only"
	case "dotenv":
		return "a .env file on the agent's machine"
	case "onepassword":
		return "1Password"
	case "bitwarden":
		return "Bitwarden"
	case "vault":
		return "HashiCorp Vault"
	case "infisical":
		return "Infisical"
	case "doppler":
		return "Doppler"
	case "aws":
		return "AWS Secrets Manager"
	case "gcp":
		return "Google Secret Manager"
	case "azure":
		return "Azure Key Vault"
	case "":
		return "the configured storage"
	}
	return backend
}

func describeRetention(retention string, expires time.Time) string {
	switch {
	case retention == "session":
		return "kept only until the agent process exits"
	case retention == "until-revoked":
		return "kept until deleted"
	case !expires.IsZero():
		return "kept until " + expires.UTC().Format("2006-01-02 15:04 UTC")
	case strings.HasPrefix(retention, "until:"):
		return "kept until " + strings.TrimPrefix(retention, "until:")
	}
	return retention
}

// requestMessage is the disclosure text the model relays to the human. It
// contains everything the human must know: what is asked and why, where it
// will be stored and for how long, that the link opens once and expires,
// and the fingerprint to compare.
func requestMessage(out RequestOutput, in RequestInput) string {
	return fmt.Sprintf("Please share %s using this one-time secure link: %s\n\nWhat it is for: %s\nWhere it will be stored: %s (%s).\nThe link works once and expires at %s. Before submitting, check that the page shows fingerprint %s. The secret is encrypted in your browser and only this agent can decrypt it; the relay never sees it. I will never see the value itself.",
		in.Name, out.Link, in.Purpose, describeStorage(out.Storage), describeRetention(out.Retention, time.Time{}), out.ExpiresAt.Format("2006-01-02 15:04 UTC"), out.Fingerprint)
}

func sendMessage(out SendOutput, name string) string {
	copyNote := "I keep my copy of it."
	if !out.KeepsCopy {
		copyNote = "I have deleted my copy of it."
	}
	passwordNote := ""
	if out.PasswordProtected {
		passwordNote = " The page asks for your reveal password before it shows the value."
	}
	return fmt.Sprintf("Here is %s: %s\n\nThe link reveals the value once, after you press the button on the page, and then it is gone.%s It expires at %s. %s Copy the value somewhere safe before closing the page.",
		name, out.Link, passwordNote, out.ExpiresAt.Format("2006-01-02 15:04 UTC"), copyNote)
}
