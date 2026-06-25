//go:build windows

package keyring

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32            = windows.NewLazySystemDLL("advapi32.dll")
	procInitializeAcl      = modadvapi32.NewProc("InitializeAcl")
	procAddAccessAllowedAce = modadvapi32.NewProc("AddAccessAllowedAce")
)

const aclRevision = 2

// secureKeyFile replaces the key file's DACL with a fresh, non-inheritable
// DACL granting Full Control exclusively to the current user, SYSTEM, and
// BUILTIN\Administrators. All pre-existing ACEs — both inherited entries (the
// B5 scenario: a project directory outside %USERPROFILE% whose DACL includes
// BUILTIN\Users:(RX)) and any explicit entries an attacker may have planted
// before the file was written — are discarded. os.Chmod (mode 0600) does not
// configure the DACL on Windows; without this call the private key would
// remain readable by all local users on directories that inherit permissive
// parent DACLs, and checkKeyFileOwnership would refuse to load it.
func secureKeyFile(path string) error {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("get current user SID for key file DACL: %w", err)
	}

	acl, aclBuf, err := buildOwnerOnlyACL(tokenUser.User.Sid)
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("build key file DACL (file removed to avoid leaving insecure key): %w", err)
	}

	// PROTECTED_DACL_SECURITY_INFORMATION prevents the OS from merging in
	// inheritable ACEs from the parent directory after we set the new DACL —
	// the same effect as icacls /inheritance:r, but applied atomically as part
	// of the SetNamedSecurityInfo call rather than as a separate step.
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
	runtime.KeepAlive(aclBuf) // keep backing allocation alive through the syscall
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("set key file DACL (file removed to avoid leaving insecure key): %w", err)
	}
	return nil
}

// buildOwnerOnlyACL constructs a minimal DACL granting Full Control to
// ownerSid, NT AUTHORITY\SYSTEM, and BUILTIN\Administrators only. The returned
// aclBuf is the backing allocation for acl; callers must runtime.KeepAlive it
// until after the last use of acl.
func buildOwnerOnlyACL(ownerSid *windows.SID) (acl *windows.ACL, aclBuf []byte, err error) {
	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, fmt.Errorf("create SYSTEM SID: %w", err)
	}
	adminsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, nil, fmt.Errorf("create Administrators SID: %w", err)
	}

	sids := []*windows.SID{ownerSid, systemSid, adminsSid}
	// ACL header is 8 bytes; each ACCESS_ALLOWED_ACE is 8 bytes of fixed
	// header + the SID length. Windows aligns ACE sizes to DWORD boundaries,
	// but GetLengthSid already returns a DWORD-aligned value.
	aclSize := uint32(8)
	for _, sid := range sids {
		aclSize += 8 + windows.GetLengthSid(sid)
	}

	aclBuf = make([]byte, aclSize)
	acl = (*windows.ACL)(unsafe.Pointer(&aclBuf[0])) //nolint:gosec // G103: raw pointer into our own heap allocation; safe for the Windows ACL in-place layout.

	r, _, e := procInitializeAcl.Call(
		uintptr(unsafe.Pointer(acl)), //nolint:gosec // G103: same allocation as above.
		uintptr(aclSize),
		uintptr(aclRevision),
	)
	if r == 0 {
		return nil, nil, fmt.Errorf("InitializeAcl: %w", e)
	}

	const fullControl = 0x1F01FF // FILE_ALL_ACCESS
	for _, sid := range sids {
		r, _, e := procAddAccessAllowedAce.Call(
			uintptr(unsafe.Pointer(acl)), //nolint:gosec // G103: same allocation as above.
			uintptr(aclRevision),
			uintptr(fullControl),
			uintptr(unsafe.Pointer(sid)), //nolint:gosec // G103: SID pointer from CreateWellKnownSid / GetTokenUser — valid for the duration of this call.
		)
		if r == 0 {
			return nil, nil, fmt.Errorf("AddAccessAllowedAce for %s: %w", sid, e)
		}
	}

	return acl, aclBuf, nil
}

// checkKeyFileOwnership verifies that the key file at path is owned by the
// current user and does not have a null DACL. A null DACL grants unrestricted
// access to every account on the machine and would expose the private key to
// any local user.
func checkKeyFileOwnership(path string) error {
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
	// runners), new files are owned by BUILTIN\Administrators rather than the
	// specific user SID. SYSTEM-owned files are similarly safe. The threat model
	// is files owned by a completely different unprivileged account, not by
	// admin groups.
	systemSid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("create SYSTEM SID for owner check: %w", err)
	}
	adminsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID for owner check: %w", err)
	}
	if !owner.Equals(tokenUser.User.Sid) && !owner.Equals(systemSid) && !owner.Equals(adminsSid) {
		return fmt.Errorf("file is owned by a different user account — possible key substitution attack")
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("get DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("key file has a null DACL — all local accounts can read it; re-run `envseal keygen` to regenerate with secure permissions")
	}

	return checkKeyFileDACLEntries(dacl, tokenUser.User.Sid)
}

// checkKeyFileDACLEntries enumerates all ACCESS_ALLOWED ACEs in dacl and
// rejects any ACE that grants access to an account other than ownerSid,
// SYSTEM, or the built-in Administrators group. This prevents pre-creation
// attacks where an adversary places the key file with the victim's owner SID
// but includes a world-readable ACE, bypassing the null-DACL and owner-SID
// checks. Inherit-only ACEs are skipped — they apply only to child objects.
func checkKeyFileDACLEntries(dacl *windows.ACL, ownerSid *windows.SID) error {
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
		// DENY and AUDIT ACEs restrict or audit; only ALLOW ACEs grant access.
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
		return fmt.Errorf("key file DACL grants access to unexpected account %s — possible key substitution attack; delete the key file and re-run `envseal keygen`", aceSid.String())
	}
	return nil
}
