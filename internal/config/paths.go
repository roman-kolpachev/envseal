package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
)

const (
	DirName    = ".envseal"
	ConfigFile = "config.toml"
	AuditFile  = "audit.log"
	KeysFile   = "keys"
	VaultDir   = "vault"
)

// maxFindProjectDirDepth mirrors keyring.maxDiscoverDepth: both walk upward
// from a starting directory looking for a piece of an initialized project
// (config.toml here, the keys file there), and both need the same bound so
// neither search wanders further than the other into unrelated ancestor
// directories (e.g. stopping at a home or filesystem root boundary).
const maxFindProjectDirDepth = 20

// FindProjectDir walks upward from start looking for .envseal/config.toml,
// mirroring keyring.Discover's own upward walk for the private key file.
// Without this, running any command from a subdirectory of an initialized
// project (e.g. a monorepo's apps/backend/ while .envseal/ lives at the
// repo root — or simply cd'ing into a nested folder) fails with "not
// initialized", which is not just inconvenient but actively misleading: a
// user who follows that message and runs `envseal init` right there creates
// a second, disconnected .envseal/ tree nested inside the real project,
// silently splitting their secrets across two unrelated vaults.
func FindProjectDir(start string) (string, error) {
	current := start
	for depth := 0; depth < maxFindProjectDirDepth; depth++ {
		if info, err := os.Lstat(ConfigPath(current)); err == nil && info.Mode().IsRegular() {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", fmt.Errorf("no %s/%s found in %q or any parent directory", DirName, ConfigFile, start)
}

func DirPath(projectDir string) string {
	return filepath.Join(projectDir, DirName)
}

func ConfigPath(projectDir string) string {
	return filepath.Join(projectDir, DirName, ConfigFile)
}

func AuditPath(projectDir string) string {
	return filepath.Join(projectDir, DirName, AuditFile)
}

func KeysPath(projectDir string) string {
	return filepath.Join(projectDir, DirName, KeysFile)
}

func VaultDirPath(projectDir string) string {
	return filepath.Join(projectDir, DirName, VaultDir)
}

func VaultFilePath(envName string) string {
	// Use path.Join (always forward-slash) not filepath.Join: this value is
	// stored in config.toml which is committed to git and read on any OS. A
	// backslash produced by filepath.Join on Windows would be treated as a
	// literal filename character on Linux, making cross-platform teams' vaults
	// inaccessible after the config is generated on a Windows machine.
	return path.Join(DirName, VaultDir, envName+".vault")
}
