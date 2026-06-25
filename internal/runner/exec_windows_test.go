//go:build windows

package runner

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// setNullDACL mirrors the exact call sequence manually verified against a
// real Windows machine in WINDOWS_TESTING.md's null-DACL test: passing
// DACL_SECURITY_INFORMATION with a nil dacl argument sets a null DACL.
func setNullDACL(t *testing.T, path string) {
	t.Helper()
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil,
	); err != nil {
		t.Fatalf("SetNamedSecurityInfo(null DACL): %v", err)
	}
}

// grantEveryone adds a world-writable ACE via icacls (merges into the
// existing DACL rather than replacing it) — simulates the pre-creation
// attack checkDACLEntries exists to catch: an adversary pre-creates
// XDG_RUNTIME_DIR (or the fallback temp directory) owned by the victim but
// with an extra world-accessible ACE.
func grantEveryone(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("icacls", path, "/grant", "Everyone:(F)").CombinedOutput()
	if err != nil {
		t.Fatalf("icacls /grant Everyone: %v: %s", err, out)
	}
}

// TestValidateWindowsOwnership_NormalDirPasses verifies that a freshly created
// temp directory passes the ownership check. On elevated Windows processes
// (including GitHub Actions windows-latest runners), new directories are owned
// by BUILTIN\Administrators rather than the specific user SID — validateWindowsOwnership
// accepts that as a valid owner alongside the current user and SYSTEM.
func TestValidateWindowsOwnership_NormalDirPasses(t *testing.T) {
	dir := t.TempDir()
	if err := validateWindowsOwnership(dir); err != nil {
		t.Errorf("validateWindowsOwnership(freshly created temp dir) = %v, want nil", err)
	}
}

func TestValidateWindowsOwnership_RejectsNullDACL(t *testing.T) {
	dir := t.TempDir()
	setNullDACL(t, dir)

	if err := validateWindowsOwnership(dir); err == nil {
		t.Fatal("validateWindowsOwnership should reject a null DACL")
	}
}

func TestValidateWindowsOwnership_RejectsExtraACE(t *testing.T) {
	dir := t.TempDir()
	grantEveryone(t, dir)

	if err := validateWindowsOwnership(dir); err == nil {
		t.Fatal("validateWindowsOwnership should reject a DACL granting access to Everyone")
	}
}

func TestSanitizeUsername(t *testing.T) {
	cases := []struct {
		env  string
		want string
	}{
		{"roman", "roman"},
		{"roman user@domain", "romanuserdomain"},
		{"@#$%^&", "unknown"},
		{"", "unknown"},
		{"Roman-Kolpachev_2026", "Roman-Kolpachev_2026"},
	}
	for _, tt := range cases {
		t.Setenv("USERNAME", tt.env)
		if got := sanitizeUsername(); got != tt.want {
			t.Errorf("sanitizeUsername() with USERNAME=%q = %q, want %q", tt.env, got, tt.want)
		}
	}
}

// TestUserTempDir_CreatesSecureDirectory exercises the real
// %TEMP%\.envseal-<username> path — userTempDir doesn't take an override, so
// this can't be redirected to an isolated t.TempDir(). Runs are not
// independent: a prior run's directory is reused, which is deliberately part
// of what's under test (userTempDir must still validate correctly against an
// already-existing directory, not just a freshly created one).
func TestUserTempDir_CreatesSecureDirectory(t *testing.T) {
	dir, err := userTempDir()
	if err != nil {
		t.Fatalf("userTempDir: %v", err)
	}
	info, statErr := os.Stat(dir)
	if statErr != nil || !info.IsDir() {
		t.Errorf("userTempDir() = %q, want an existing directory", dir)
	}
}
