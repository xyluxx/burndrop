package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// awsFake simulates the aws CLI's secretsmanager and sts commands with the
// JSON shapes from the command reference: exit code 254 with "An error
// occurred (<Exception>) when calling the <Op> operation" for service errors,
// 255 when no credentials are found.
type awsFake struct {
	mu       sync.Mutex
	signedIn bool
	secrets  map[string]*awsFakeSecret
	files    []string      // file:// paths the CLI was pointed at
	modes    []os.FileMode // their permission bits when read
}

type awsFakeSecret struct {
	value    string
	versions int
	deleted  bool // scheduled for deletion with a recovery window
}

const (
	awsFakeARN  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:"
	awsFakeTime = "2026-09-17T01:02:03.123000+00:00"
)

func newAWSFake() *awsFake {
	return &awsFake{signedIn: true, secrets: map[string]*awsFakeSecret{}}
}

// awsParseArgs splits aws CLI arguments into positionals and --flag values.
func awsParseArgs(args []string) (pos []string, flags map[string]string) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			flags[a] = args[i+1]
			i++
		} else {
			flags[a] = "true"
		}
	}
	return pos, flags
}

func (f *awsFake) notFound(op string) error {
	return exitError("aws", 254, fmt.Sprintf("An error occurred (ResourceNotFoundException) when calling the %s operation: Secrets Manager can't find the specified secret.", op))
}

// readSecretString resolves --secret-string the way the CLI does: a file://
// reference is read from disk. A literal value is refused because burndrop
// must never pass the value as an argument.
func (f *awsFake) readSecretString(arg string) (string, error) {
	path, ok := strings.CutPrefix(arg, "file://")
	if !ok {
		return "", fmt.Errorf("fake aws: --secret-string must be a file:// reference, got %q", arg)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	f.files = append(f.files, path)
	f.modes = append(f.modes, info.Mode().Perm())
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) > awsMaxRecordBytes {
		return "", exitError("aws", 252, "An error occurred (ValidationException): 1 validation error detected: Value at 'secretString' failed to satisfy constraint: Member must have length less than or equal to 65536")
	}
	return string(b), nil
}

func (f *awsFake) handler(call fakeCall) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if call.Name != "aws" {
		return nil, fmt.Errorf("unexpected command %s", call.Name)
	}
	if call.Stdin != nil {
		return nil, errors.New("fake aws: nothing is expected on stdin")
	}
	pos, flags := awsParseArgs(call.Args)
	if flags["--output"] != "json" {
		return nil, errors.New("fake aws: --output json is required")
	}
	if !f.signedIn {
		return nil, exitError("aws", 255, "Unable to locate credentials. You can configure credentials by running \"aws configure\".")
	}
	if len(pos) < 2 {
		return nil, errors.New("fake aws: missing service or operation")
	}
	switch op := pos[0] + " " + pos[1]; op {
	case "sts get-caller-identity":
		return []byte(`{"UserId": "AIDASAMPLEUSERID", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/DevAdmin"}`), nil
	case "secretsmanager create-secret":
		name := flags["--name"]
		if s, ok := f.secrets[name]; ok {
			if s.deleted {
				return nil, exitError("aws", 254, "An error occurred (InvalidRequestException) when calling the CreateSecret operation: You can't create this secret because a secret with this name is already scheduled for deletion.")
			}
			return nil, exitError("aws", 254, fmt.Sprintf("An error occurred (ResourceExistsException) when calling the CreateSecret operation: The operation failed because the secret %s already exists.", name))
		}
		value, err := f.readSecretString(flags["--secret-string"])
		if err != nil {
			return nil, err
		}
		f.secrets[name] = &awsFakeSecret{value: value, versions: 1}
		return json.Marshal(map[string]any{"ARN": awsFakeARN + name + "-AbCdEf", "Name": name, "VersionId": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"})
	case "secretsmanager put-secret-value":
		name := flags["--secret-id"]
		s, ok := f.secrets[name]
		if !ok {
			return nil, f.notFound("PutSecretValue")
		}
		if s.deleted {
			return nil, exitError("aws", 254, "An error occurred (InvalidRequestException) when calling the PutSecretValue operation: You can't perform this operation on the secret because it was marked for deletion.")
		}
		value, err := f.readSecretString(flags["--secret-string"])
		if err != nil {
			return nil, err
		}
		s.value = value
		s.versions++
		return json.Marshal(map[string]any{"ARN": awsFakeARN + name + "-AbCdEf", "Name": name, "VersionId": fmt.Sprintf("a1b2c3d4-5678-90ab-cdef-EXAMPLE%05d", s.versions), "VersionStages": []string{"AWSCURRENT"}})
	case "secretsmanager get-secret-value":
		name := flags["--secret-id"]
		s, ok := f.secrets[name]
		if !ok {
			return nil, f.notFound("GetSecretValue")
		}
		if s.deleted {
			return nil, exitError("aws", 254, "An error occurred (InvalidRequestException) when calling the GetSecretValue operation: You can't perform this operation on the secret because it was marked for deletion.")
		}
		return json.Marshal(map[string]any{"ARN": awsFakeARN + name + "-AbCdEf", "Name": name, "VersionId": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111", "SecretString": s.value, "VersionStages": []string{"AWSCURRENT"}, "CreatedDate": awsFakeTime})
	case "secretsmanager describe-secret":
		name := flags["--secret-id"]
		s, ok := f.secrets[name]
		if !ok {
			return nil, f.notFound("DescribeSecret")
		}
		item := f.listItem(name)
		if s.deleted {
			item["DeletedDate"] = "2026-10-17T01:02:03.123000+00:00"
		}
		return json.Marshal(item)
	case "secretsmanager delete-secret":
		name := flags["--secret-id"]
		s, ok := f.secrets[name]
		if flags["--force-delete-without-recovery"] == "true" {
			// A forced delete of a missing secret succeeds, as documented.
			delete(f.secrets, name)
		} else {
			if !ok {
				return nil, f.notFound("DeleteSecret")
			}
			s.deleted = true
		}
		return json.Marshal(map[string]any{"ARN": awsFakeARN + name + "-AbCdEf", "Name": name, "DeletionDate": awsFakeTime})
	case "secretsmanager list-secrets":
		prefix := ""
		for _, part := range strings.Split(flags["--filters"], ",") {
			if v, ok := strings.CutPrefix(part, "Values="); ok {
				prefix = v
			}
		}
		out := []map[string]any{}
		for name, s := range f.secrets {
			if strings.HasPrefix(name, prefix) && !s.deleted {
				out = append(out, f.listItem(name))
			}
		}
		return json.Marshal(map[string]any{"SecretList": out})
	default:
		return nil, fmt.Errorf("fake aws: unknown operation %q", op)
	}
}

func (f *awsFake) listItem(name string) map[string]any {
	return map[string]any{
		"ARN":                    awsFakeARN + name + "-AbCdEf",
		"Name":                   name,
		"Description":            "burndrop record",
		"LastChangedDate":        awsFakeTime,
		"LastAccessedDate":       awsFakeTime,
		"CreatedDate":            awsFakeTime,
		"SecretVersionsToStages": map[string][]string{"a1b2c3d4-5678-90ab-cdef-EXAMPLE11111": {"AWSCURRENT"}},
	}
}

func awsHasArgs(args []string, want ...string) bool {
	for i := 0; i+len(want) <= len(args); i++ {
		match := true
		for j := range want {
			if args[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestAWSBackend(t *testing.T) {
	runBackendSuite(t, func(t *testing.T) Backend {
		return NewAWS(AWS{Runner: newFakeRunner(newAWSFake().handler)})
	}, awsMaxValueBytes)

	ctx := context.Background()
	meta := Metadata{Retention: RetentionUntilRevoked, Purpose: "test"}

	t.Run("value only through a temporary file", func(t *testing.T) {
		fake := newAWSFake()
		runner := newFakeRunner(fake.handler)
		b := NewAWS(AWS{Runner: runner, Region: "eu-west-1", Profile: "dev"})
		secret := []byte("sk-live-1234 with \x00 and \xff")
		if err := b.Put(ctx, "api-key", secret, meta); err != nil {
			t.Fatal(err)
		}
		if v, _, err := b.Get(ctx, "api-key"); err != nil || string(v) != string(secret) {
			t.Fatalf("get: %v", err)
		}
		runner.assertNoSecretInArgs(t, secret)
		runner.assertNoSecretInArgs(t, []byte(base64.StdEncoding.EncodeToString(secret)))
		if len(fake.files) != 1 {
			t.Fatalf("expected one temp file, saw %v", fake.files)
		}
		if _, err := os.Stat(fake.files[0]); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temp file still exists: %v", err)
		}
		if filepath.Dir(fake.files[0]) != filepath.Clean(os.TempDir()) {
			t.Fatalf("temp file outside os.TempDir: %s", fake.files[0])
		}
		if runtime.GOOS != "windows" && fake.modes[0] != 0o600 {
			t.Fatalf("temp file mode %o, want 0600", fake.modes[0])
		}
		for _, c := range runner.Calls() {
			if !awsHasArgs(c.Args, "--region", "eu-west-1") || !awsHasArgs(c.Args, "--profile", "dev") || !awsHasArgs(c.Args, "--output", "json") {
				t.Fatalf("missing region, profile or output flags: %v", c.Args)
			}
			for i, a := range c.Args {
				if a == "--secret-string" && !strings.HasPrefix(c.Args[i+1], "file://") {
					t.Fatalf("secret string not passed as a file: %v", c.Args)
				}
			}
			if len(c.Env) != 1 || c.Env[0] != "AWS_CLI_FILE_ENCODING=UTF-8" {
				t.Fatalf("unexpected environment: %v", c.Env)
			}
		}
	})

	t.Run("overwrite adds a version", func(t *testing.T) {
		fake := newAWSFake()
		runner := newFakeRunner(fake.handler)
		b := NewAWS(AWS{Runner: runner})
		for _, v := range []string{"one", "two"} {
			if err := b.Put(ctx, "k", []byte(v), meta); err != nil {
				t.Fatal(err)
			}
		}
		var ops []string
		for _, c := range runner.Calls() {
			ops = append(ops, c.Args[1])
		}
		if strings.Join(ops, ",") != "create-secret,create-secret,put-secret-value" {
			t.Fatalf("operations: %v", ops)
		}
		if fake.secrets["burndrop/k"].versions != 2 {
			t.Fatalf("versions: %d", fake.secrets["burndrop/k"].versions)
		}
	})

	t.Run("binary missing", func(t *testing.T) {
		runner := newFakeRunner(newAWSFake().handler)
		runner.setMissing("aws", true)
		p := NewAWS(AWS{Runner: runner}).Probe(ctx)
		if p.Available || !strings.Contains(p.Reason, "install AWS CLI v2") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("not signed in", func(t *testing.T) {
		fake := newAWSFake()
		fake.signedIn = false
		b := NewAWS(AWS{Runner: newFakeRunner(fake.handler)})
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "aws configure") {
			t.Fatalf("probe: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("put: %v", err)
		}
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("get: %v", err)
		}
		if _, err := b.List(ctx); !errors.Is(err, ErrPermission) {
			t.Fatalf("list: %v", err)
		}
	})

	t.Run("probe reason", func(t *testing.T) {
		p := NewAWS(AWS{Runner: newFakeRunner(newAWSFake().handler), Region: "us-east-1"}).Probe(ctx)
		if !p.Available || p.Rank != 91 || !strings.Contains(p.Reason, "user/DevAdmin") || !strings.Contains(p.Reason, "123456789012") || !strings.Contains(p.Reason, "us-east-1") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("not found", func(t *testing.T) {
		runner := newFakeRunner(newAWSFake().handler)
		b := NewAWS(AWS{Runner: runner})
		if _, _, err := b.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get: %v", err)
		}
		if err := b.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete: %v", err)
		}
		for _, c := range runner.Calls() {
			if c.Args[1] == "delete-secret" {
				t.Fatal("delete-secret called for a missing secret")
			}
		}
	})

	t.Run("scheduled for deletion counts as gone", func(t *testing.T) {
		fake := newAWSFake()
		b := NewAWS(AWS{Runner: newFakeRunner(fake.handler)})
		if err := b.Put(ctx, "k", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		fake.secrets["burndrop/k"].deleted = true
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get: %v", err)
		}
		if err := b.Delete(ctx, "k"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete: %v", err)
		}
		if err := b.Put(ctx, "k", []byte("v2"), meta); err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "scheduled for deletion") {
			t.Fatalf("put: %v", err)
		}
		if list, err := b.List(ctx); err != nil || len(list) != 0 {
			t.Fatalf("list: %v %v", list, err)
		}
	})

	t.Run("foreign or mismatched records", func(t *testing.T) {
		fake := newAWSFake()
		b := NewAWS(AWS{Runner: newFakeRunner(fake.handler)})
		if err := b.Put(ctx, "good", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		rec, _ := encodeRecord(Metadata{Name: "other"}, []byte("v"))
		fake.secrets["burndrop/renamed"] = &awsFakeSecret{value: string(rec)}
		fake.secrets["burndrop/plain"] = &awsFakeSecret{value: "hunter2"}
		if _, _, err := b.Get(ctx, "renamed"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("mismatched name: %v", err)
		}
		if _, _, err := b.Get(ctx, "plain"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign value: %v", err)
		}
		list, err := b.List(ctx)
		if err != nil || len(list) != 1 || list[0].Name != "good" {
			t.Fatalf("list: %+v %v", list, err)
		}
	})

	t.Run("limits", func(t *testing.T) {
		b := NewAWS(AWS{Runner: newFakeRunner(newAWSFake().handler)})
		if err := b.Put(ctx, "big", make([]byte, awsMaxValueBytes+1), meta); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("over the value limit: %v", err)
		}
		if err := b.Put(ctx, "fits", make([]byte, awsMaxValueBytes), meta); err != nil {
			t.Fatalf("at the value limit: %v", err)
		}
		wide := meta
		wide.Purpose = strings.Repeat("p", 2000)
		if err := b.Put(ctx, "wide", make([]byte, awsMaxValueBytes), wide); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("record over the SecretString limit: %v", err)
		}
	})

	t.Run("prefix validation", func(t *testing.T) {
		b := NewAWS(AWS{Runner: newFakeRunner(newAWSFake().handler), Prefix: "bad,prefix/"})
		if p := b.Probe(ctx); p.Available {
			t.Fatalf("probe: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("put: %v", err)
		}
		if _, err := b.List(ctx); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("list: %v", err)
		}
	})
}
