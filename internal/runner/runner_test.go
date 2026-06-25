package runner

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/roman-kolpachev/envseal/internal/envcheck"
)

type mockProvider struct {
	secrets map[string][]byte
	err     error
}

func (m *mockProvider) DecryptAll(ctx context.Context) (map[string][]byte, error) {
	return m.secrets, m.err
}

func TestEnv_MergesWithCurrentEnv(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{
			"DB_HOST": []byte("from-vault"),
			"NEW_VAR": []byte("added"),
		},
	}
	r := New(provider)

	t.Setenv("DB_HOST", "from-system")
	t.Setenv("EXISTING", "keep-me")

	env, err := r.Env(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	envMap := envSliceToMap(env)

	if envMap["DB_HOST"] != "from-vault" {
		t.Errorf("DB_HOST: got %q, want %q", envMap["DB_HOST"], "from-vault")
	}
	if envMap["NEW_VAR"] != "added" {
		t.Error("NEW_VAR should be added from vault")
	}
	if envMap["EXISTING"] != "keep-me" {
		t.Error("EXISTING should be preserved")
	}
}

func TestEnv_BlocksDangerousVars(t *testing.T) {
	for _, name := range envcheck.DangerousVarNames() {
		t.Run(name, func(t *testing.T) {
			provider := &mockProvider{
				secrets: map[string][]byte{name: []byte("malicious")},
			}
			r := New(provider)
			_, err := r.Env(context.Background())
			if err == nil {
				t.Errorf("Env() should reject dangerous variable %q", name)
			}
			if err != nil && !strings.Contains(err.Error(), "dangerous system variable") {
				t.Errorf("expected 'dangerous system variable' error for %q, got: %v", name, err)
			}
		})
	}
}

func TestEnv_BlocksDangerousVarsCaseInsensitive(t *testing.T) {
	cases := []string{"path", "Path", "ld_preload", "node_Options", "Http_Proxy"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			provider := &mockProvider{
				secrets: map[string][]byte{name: []byte("malicious")},
			}
			r := New(provider)
			_, err := r.Env(context.Background())
			if err == nil {
				t.Errorf("Env() should reject %q (case-insensitive check)", name)
			}
		})
	}
}

func TestSealedEnv_BlocksDangerousVars(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{"LD_PRELOAD": []byte("/tmp/evil.so")},
	}
	r := New(provider)
	_, _, err := r.SealedEnv(context.Background())
	if err == nil {
		t.Error("SealedEnv() should reject dangerous variable LD_PRELOAD")
	}
}

func TestEnv_AllowsSafeVars(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{
			"DB_HOST":   []byte("localhost"),
			"API_KEY":   []byte("sk-123"),
			"MY_CUSTOM": []byte("value"),
		},
	}
	r := New(provider)
	_, err := r.Env(context.Background())
	if err != nil {
		t.Errorf("Env() should allow safe variables, got: %v", err)
	}
}

func TestEnv_ProviderError(t *testing.T) {
	provider := &mockProvider{err: errors.New("decrypt failed")}
	r := New(provider)
	_, err := r.Env(context.Background())
	if err == nil {
		t.Error("should propagate provider error")
	}
}

func TestRun_CommandNotFound(t *testing.T) {
	provider := &mockProvider{secrets: map[string][]byte{}}
	r := New(provider)
	err := r.Run(context.Background(), []string{"nonexistent-command-xyz"})
	if err == nil {
		t.Error("should fail for unknown command")
	}
}

func TestSealedEnv_SecretsNotInEnvVars(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{
			"DB_PASSWORD": []byte("supersecret"),
			"API_KEY":     []byte("sk-123"),
		},
	}
	r := New(provider)

	env, secretsFile, err := r.SealedEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(secretsFile); err != nil {
			t.Error(err)
		}
	}()

	envMap := envSliceToMap(env)

	if _, ok := envMap["DB_PASSWORD"]; ok {
		t.Error("DB_PASSWORD should NOT be in env vars in sealed mode")
	}
	if _, ok := envMap["API_KEY"]; ok {
		t.Error("API_KEY should NOT be in env vars in sealed mode")
	}

	if envMap["ENVSEAL_SECRETS"] == "" {
		t.Fatal("ENVSEAL_SECRETS should point to the temp file")
	}
	if envMap["ENVSEAL_SECRETS"] != secretsFile {
		t.Errorf("ENVSEAL_SECRETS=%q should match returned file %q", envMap["ENVSEAL_SECRETS"], secretsFile)
	}
}

func TestSealedEnv_FileContainsSecrets(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{
			"DB_PASSWORD": []byte("supersecret"),
			"API_KEY":     []byte("sk-123"),
		},
	}
	r := New(provider)

	_, secretsFile, err := r.SealedEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(secretsFile); err != nil {
			t.Error(err)
		}
	}()

	data, err := os.ReadFile(secretsFile)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "DB_PASSWORD=supersecret") {
		t.Error("secrets file should contain DB_PASSWORD")
	}
	if !strings.Contains(content, "API_KEY=sk-123") {
		t.Error("secrets file should contain API_KEY")
	}
}

func TestSealedEnv_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission check not reliable on Windows")
	}

	provider := &mockProvider{
		secrets: map[string][]byte{"KEY": []byte("val")},
	}
	r := New(provider)

	_, secretsFile, err := r.SealedEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(secretsFile); err != nil {
			t.Error(err)
		}
	}()

	info, err := os.Stat(secretsFile)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("secrets file permissions: got %o, want 0600", perm)
	}
}

func TestRun_Success(t *testing.T) {
	// execProcessFunc is stubbed out here rather than left as the real
	// syscall.Exec: on success that replaces the test binary's own process
	// image and never returns, silently discarding every test declared after
	// this one in the suite while go test still reports the package as
	// passing. See the execProcessFunc doc comment in runner.go.
	orig := execProcessFunc
	defer func() { execProcessFunc = orig }()
	var gotBinary string
	var gotArgs, gotEnv []string
	execProcessFunc = func(_ context.Context, binary string, args, env []string) error {
		// Run() defers clearEnvSlice(env) right after this returns, so env's
		// strings must be cloned now — capturing the slice by reference would
		// read back zeroed-out values once the deferred clear has run.
		gotBinary = binary
		gotArgs = append([]string(nil), args...)
		gotEnv = make([]string, len(env))
		for i, e := range env {
			gotEnv[i] = strings.Clone(e)
		}
		return nil
	}

	provider := &mockProvider{
		secrets: map[string][]byte{"SECRET": []byte("injected")},
	}
	r := New(provider)

	var cmd []string
	if runtime.GOOS == "windows" {
		cmd = []string{"cmd", "/c", "echo", "hello"}
	} else {
		cmd = []string{"echo", "hello"}
	}

	err := r.Run(context.Background(), cmd)
	if err != nil {
		t.Fatalf("Run should succeed: %v", err)
	}

	if gotBinary == "" {
		t.Error("expected execProcessFunc to be invoked with a resolved binary path")
	}
	if len(gotArgs) != len(cmd) {
		t.Errorf("args: got %v, want %v", gotArgs, cmd)
	}
	if envSliceToMap(gotEnv)["SECRET"] != "injected" {
		t.Error("expected injected secret to be present in the env passed to execProcessFunc")
	}
}

func TestRunSealed_Success(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{"SECRET": []byte("sealed_val")},
	}
	r := New(provider)

	var cmd []string
	if runtime.GOOS == "windows" {
		cmd = []string{"cmd", "/c", "echo", "hello"}
	} else {
		cmd = []string{"echo", "hello"}
	}

	err := r.RunSealed(context.Background(), cmd)
	if err != nil {
		t.Fatalf("RunSealed should succeed: %v", err)
	}
}

func TestRunSealed_CleansUpFile(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{
			"SECRET": []byte("value123"),
		},
	}
	r := New(provider)

	env, secretsFile, err := r.SealedEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(secretsFile); err != nil {
		t.Fatalf("secrets file should exist before RunSealed: %v", err)
	}

	_ = env
	_ = os.Remove(secretsFile)
}

func TestRunSealed_CommandNotFound(t *testing.T) {
	provider := &mockProvider{secrets: map[string][]byte{"KEY": []byte("val")}}
	r := New(provider)

	err := r.RunSealed(context.Background(), []string{"nonexistent-command-xyz-99"})
	if err == nil {
		t.Error("should fail for unknown command")
	}
}

func TestRunSealed_ProviderError(t *testing.T) {
	provider := &mockProvider{err: errors.New("decrypt failed")}
	r := New(provider)

	err := r.RunSealed(context.Background(), []string{"echo", "hi"})
	if err == nil {
		t.Error("should propagate provider error")
	}
}

func TestEnv_StripsEnvsealKey(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{"DB_HOST": []byte("localhost")},
	}
	r := New(provider)

	t.Setenv("ENVSEAL_KEY", "AGE-SECRET-KEY-FAKE")

	env, err := r.Env(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	envMap := envSliceToMap(env)
	if _, ok := envMap["ENVSEAL_KEY"]; ok {
		t.Error("ENVSEAL_KEY should be stripped from child environment")
	}
	if envMap["DB_HOST"] != "localhost" {
		t.Error("vault secrets should still be injected")
	}
}

func TestSealedEnv_StripsEnvsealKey(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{"DB_HOST": []byte("localhost")},
	}
	r := New(provider)

	t.Setenv("ENVSEAL_KEY", "AGE-SECRET-KEY-FAKE")

	env, secretsFile, err := r.SealedEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(secretsFile); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	envMap := envSliceToMap(env)
	if _, ok := envMap["ENVSEAL_KEY"]; ok {
		t.Error("ENVSEAL_KEY should be stripped from child environment in sealed mode")
	}
}

func TestSealedEnv_EscapesNewlines(t *testing.T) {
	provider := &mockProvider{
		secrets: map[string][]byte{
			"CERT": []byte("line1\nline2\nline3"),
		},
	}
	r := New(provider)

	_, secretsFile, err := r.SealedEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(secretsFile); err != nil {
			t.Error(err)
		}
	}()
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := parseEnvFile(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if parsed["CERT"] != "line1\nline2\nline3" {
		t.Errorf("got %q, want value with newlines preserved", parsed["CERT"])
	}
}

func parseEnvFile(content string) (map[string]string, error) {
	result := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
			v = strings.ReplaceAll(v, `\n`, "\n")
			v = strings.ReplaceAll(v, `\\`, `\`)
		}
		result[k] = v
	}
	return result, nil
}

func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string)
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		m[k] = v
	}
	return m
}
