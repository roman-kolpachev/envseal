//go:build windows

package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func execProcess(ctx context.Context, binary string, args, env []string) error {
	//nolint:gosec // G204: executing the user-specified command is this tool's entire purpose ("envseal run -- CMD"); binary is resolved via exec.LookPath, not passed through a shell.
	cmd := exec.CommandContext(ctx, binary, args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cleanupSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func validateTempDirSecurity(info os.FileInfo) bool {
	if !info.IsDir() {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return true
}

// validateTempDirOwnership verifies the DACL and owner of a candidate
// runtime/temp directory (e.g. one supplied via XDG_RUNTIME_DIR). On Windows,
// os.FileMode permission bits are advisory — Chmod toggles only the read-only
// attribute — so the actual protection for the 0600 secrets file created
// inside is the directory's DACL. Apply the same owner + DACL validation that
// userTempDir enforces, closing the pre-created world-writable directory gap.
func validateTempDirOwnership(dir string) error {
	return validateWindowsOwnership(dir)
}

func userTempDir() (string, error) {
	base := os.TempDir()
	dir := filepath.Join(base, fmt.Sprintf(".envseal-%s", sanitizeUsername()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create user temp directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("stat user temp directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("user temp path %s is not a directory", dir)
	}
	if !validateTempDirSecurity(info) {
		return "", fmt.Errorf("user temp directory %s is a symlink or junction — refusing to use for security", dir)
	}
	if err := validateWindowsOwnership(dir); err != nil {
		return "", fmt.Errorf("user temp directory %s ownership check failed: %w", dir, err)
	}
	return dir, nil
}

func sanitizeUsername() string {
	username := os.Getenv("USERNAME")
	if username == "" {
		username = "unknown"
	}
	var b strings.Builder
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if result == "" {
		return "unknown"
	}
	return result
}

// validateWindowsOwnership verifies that path is owned by the current user and
// does not have a null DACL. Checking only the owner SID is insufficient: an
// attacker can pre-create the directory with the victim as owner but with a
// world-writable DACL (Everyone: Full Control), gaining write access while
// passing the ownership check. A null DACL grants unrestricted access to every
// account on the machine.
func validateWindowsOwnership(path string) error {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("get security info: %w", err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("get owner SID: %w", err)
	}

	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("get token user: %w", err)
	}

	// On elevated Windows processes (including GitHub Actions windows-latest
	// runners), new files and directories are owned by BUILTIN\Administrators
	// rather than the specific user SID — this is standard Windows behavior for
	// elevated tokens where the default owner is the Administrators group.
	// SYSTEM-owned paths are similarly safe. The threat model for this check is
	// paths owned by a completely different unprivileged user, not admin groups.
	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("create SYSTEM SID for owner check: %w", err)
	}
	adminsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID for owner check: %w", err)
	}
	if !owner.Equals(tokenUser.User.Sid) && !owner.Equals(systemSid) && !owner.Equals(adminsSid) {
		return fmt.Errorf("directory is owned by a different user account — possible pre-creation attack")
	}

	// A null DACL grants unrestricted access to every user on the machine.
	// A non-null DACL is enumerated below to reject world-writable ACEs.
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("get DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("temp directory has a null DACL — all local accounts can write to it; delete %s and re-run", path)
	}

	return checkDACLEntries(dacl, tokenUser.User.Sid)
}

// checkDACLEntries enumerates all ACCESS_ALLOWED ACEs in dacl and rejects any
// ACE that grants access to an account other than ownerSid, SYSTEM, or the
// built-in Administrators group. This catches pre-creation attacks where an
// adversary creates the path with the victim's SID as owner but adds a
// world-writable ACE, bypassing the null-DACL and owner-SID checks.
// Inherit-only ACEs are skipped because they apply only to child objects.
func checkDACLEntries(dacl *windows.ACL, ownerSid *windows.SID) error {
	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("create SYSTEM SID: %w", err)
	}
	adminsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID: %w", err)
	}
	creatorOwnerSid, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	if err != nil {
		return fmt.Errorf("create CreatorOwner SID: %w", err)
	}

	for i := uint32(0); ; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			break // no more ACEs
		}
		// DENY and AUDIT ACEs restrict or audit access; only ALLOW ACEs grant it.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		// Inherit-only ACEs propagate to child objects, not to the object itself.
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		aceSid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: standard Windows ACE SID extraction — ACCESS_ALLOWED_ACE.SidStart is the in-place SID per the Windows API; unsafe.Pointer is required by x/sys/windows.
		if aceSid.Equals(ownerSid) ||
			aceSid.Equals(systemSid) ||
			aceSid.Equals(adminsSid) ||
			aceSid.Equals(creatorOwnerSid) {
			continue
		}
		return fmt.Errorf("temp directory DACL grants access to unexpected account %s — possible pre-creation attack; delete the temp directory and re-run", aceSid.String())
	}
	return nil
}
