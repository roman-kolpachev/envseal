//go:build windows

package keyring

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// setNullDACL sets an explicit null DACL on path: passing DACL_SECURITY_INFORMATION
// with a nil dacl argument sets a null DACL specifically (as opposed to omitting the
// flag, which would leave the DACL untouched) — this is the exact call sequence
// manually verified against a real Windows machine while chasing B5 (see
// WINDOWS_TESTING.md). A null DACL grants unrestricted access to every account.
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

// grantEveryone adds a world-readable ACE via icacls (which merges into the
// existing DACL rather than replacing it) — simulates the pre-creation /
// inherited-permission attack that B5 found: a key file living outside
// %USERPROFILE% inherits a parent directory's permissive DACL.
func grantEveryone(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("icacls", path, "/grant", "Everyone:(R)").CombinedOutput()
	if err != nil {
		t.Fatalf("icacls /grant Everyone: %v: %s", err, out)
	}
}

// TestSecureKeyFile_RestrictsToOwnerOnly is the regression test for B5: a key
// file that inherited an overly-permissive DACL (simulated here via
// grantEveryone, standing in for the real-world case of a project directory
// outside %USERPROFILE% whose ACL includes BUILTIN\Users) must, after
// secureKeyFile runs, pass checkKeyFileOwnership — the same load-time gate
// envseal itself calls before ever trusting the key. Before the B5 fix, this
// invariant did not hold: SaveToFile relied on the 0600 mode bit, which
// Windows treats as advisory, so the file remained loadable-by-anyone and
// checkKeyFileOwnership would correctly (but unhelpfully) refuse to load the
// very key envseal had just written.
func TestSecureKeyFile_RestrictsToOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(path, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}
	grantEveryone(t, path)

	if err := secureKeyFile(path); err != nil {
		t.Fatalf("secureKeyFile: %v", err)
	}

	if err := checkKeyFileOwnership(path); err != nil {
		t.Errorf("checkKeyFileOwnership after secureKeyFile: %v, want nil", err)
	}
}

func TestCheckKeyFileOwnership_NormalFilePasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(path, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := secureKeyFile(path); err != nil {
		t.Fatal(err)
	}
	if err := checkKeyFileOwnership(path); err != nil {
		t.Errorf("checkKeyFileOwnership = %v, want nil for a freshly secured file", err)
	}
}

func TestCheckKeyFileOwnership_RejectsNullDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(path, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}
	setNullDACL(t, path)

	if err := checkKeyFileOwnership(path); err == nil {
		t.Fatal("checkKeyFileOwnership should reject a null DACL")
	}
}

// TestCheckKeyFileOwnership_RejectsExtraACE is the pre-creation-attack case
// checkKeyFileDACLEntries exists for: owner SID matches, DACL is non-null,
// but an extra ACE grants a third party access anyway.
func TestCheckKeyFileOwnership_RejectsExtraACE(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(path, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := secureKeyFile(path); err != nil {
		t.Fatal(err)
	}
	grantEveryone(t, path)

	if err := checkKeyFileOwnership(path); err == nil {
		t.Fatal("checkKeyFileOwnership should reject a DACL granting access to Everyone")
	}
}
