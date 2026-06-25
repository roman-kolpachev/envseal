package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"github.com/roman-kolpachev/envseal/internal/fileutil"
)

var validEnvName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type Environment struct {
	VaultPath  string `toml:"vault"`
	SourcePath string `toml:"source"`
}

type Config struct {
	ProjectName  string
	Default      string
	Environments map[string]Environment
	Recipients   map[string]string
}

type tomlConfig struct {
	Project      tomlProject            `toml:"project"`
	Environments map[string]Environment `toml:"environments"`
	Recipients   map[string]string      `toml:"recipients"`
}

type tomlProject struct {
	Name       string `toml:"name"`
	DefaultEnv string `toml:"default_env"`
}

func NewEnvironment(name string) Environment {
	return Environment{
		VaultPath:  VaultFilePath(name),
		SourcePath: fmt.Sprintf(".env.%s", name),
	}
}

func Default(projectName string) *Config {
	return &Config{
		ProjectName: projectName,
		Default:     "development",
		Environments: map[string]Environment{
			"development": NewEnvironment("development"),
			"staging":     NewEnvironment("staging"),
			"production":  NewEnvironment("production"),
		},
		Recipients: make(map[string]string),
	}
}

const (
	maxConfigFileSize  = 1024 * 1024 // 1 MiB
	maxEnvironments    = 50
	maxRecipients      = 100
	maxPathFieldLength = 4096
)

const maxProjectNameLength = 256

// ValidateProjectName rejects a project name containing control characters
// (terminal escape injection if the name is ever echoed) or exceeding a sane
// length. The name is free-form display metadata, so any printable content is
// allowed; empty is fine (init defaults it to the directory name). config.toml
// may come from a shared git repository, so on Load this field is
// attacker-influenced input like every other field Load validates. Exported so
// `init` can apply the same check up front — otherwise an init in a directory
// whose name contains control characters would write a config that every
// subsequent Load rejects.
func ValidateProjectName(name string) error {
	if len(name) > maxProjectNameLength {
		return fmt.Errorf("project name exceeds maximum length of %d bytes", maxProjectNameLength)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("project name contains control characters — possible terminal escape injection")
		}
	}
	return nil
}

// validatePathField rejects config-supplied paths containing control characters
// (which enable terminal escape injection when the path is echoed back to the
// user) or exceeding a sane length. Path traversal and absolute-path escapes
// are enforced separately at the point of use (cmd.safePath).
func validatePathField(field, value string) error {
	if len(value) > maxPathFieldLength {
		return fmt.Errorf("%s path exceeds maximum length of %d bytes", field, maxPathFieldLength)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s path contains control characters — possible terminal escape injection", field)
		}
	}
	return nil
}

func Load(path string) (_ *Config, err error) {
	lstatInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config %s: %w", path, err)
	}
	if !lstatInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("config path %q is not a regular file", path)
	}
	if lstatInfo.Size() > maxConfigFileSize {
		return nil, fmt.Errorf("config file %s exceeds maximum size of %d bytes", path, maxConfigFileSize)
	}

	//nolint:gosec // G304: path was just Lstat-verified above to be a regular file within size limits; this is not attacker-controlled traversal.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %s: %w", path, err)
	}
	defer func() { 
		if cerr := f.Close(); cerr != nil { 
			err = errors.Join(err, cerr) 
		} 
	}()

	fdInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open config %s: %w", path, err)
	}
	if !os.SameFile(lstatInfo, fdInfo) {
		return nil, fmt.Errorf("config file %s changed between stat and open", path)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxConfigFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if int64(len(data)) > maxConfigFileSize {
		return nil, fmt.Errorf("config file %s exceeds maximum size of %d bytes", path, maxConfigFileSize)
	}

	var tc tomlConfig
	if _, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&tc); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if tc.Environments == nil {
		tc.Environments = make(map[string]Environment)
	}
	if tc.Recipients == nil {
		tc.Recipients = make(map[string]string)
	}

	if len(tc.Environments) > maxEnvironments {
		return nil, fmt.Errorf("config contains %d environments, exceeding maximum of %d", len(tc.Environments), maxEnvironments)
	}
	if len(tc.Recipients) > maxRecipients {
		return nil, fmt.Errorf("config contains %d recipients, exceeding maximum of %d", len(tc.Recipients), maxRecipients)
	}

	if err := ValidateProjectName(tc.Project.Name); err != nil {
		return nil, fmt.Errorf("config contains invalid project name: %w", err)
	}
	if tc.Project.DefaultEnv != "" {
		if err := ValidateEnvironmentName(tc.Project.DefaultEnv); err != nil {
			return nil, fmt.Errorf("config contains invalid default_env: %w", err)
		}
	}

	for name, env := range tc.Environments {
		if err := ValidateEnvironmentName(name); err != nil {
			return nil, fmt.Errorf("config contains invalid environment: %w", err)
		}
		if err := validatePathField("vault", env.VaultPath); err != nil {
			return nil, fmt.Errorf("config environment %q: %w", name, err)
		}
		if err := validatePathField("source", env.SourcePath); err != nil {
			return nil, fmt.Errorf("config environment %q: %w", name, err)
		}
	}
	for name, key := range tc.Recipients {
		if err := ValidateRecipientName(name); err != nil {
			return nil, fmt.Errorf("config contains invalid recipient: %w", err)
		}
		if _, err := age.ParseX25519Recipient(key); err != nil {
			return nil, fmt.Errorf("config contains invalid public key for recipient %q: %w", name, err)
		}
	}

	return &Config{
		ProjectName:  tc.Project.Name,
		Default:      tc.Project.DefaultEnv,
		Environments: tc.Environments,
		Recipients:   tc.Recipients,
	}, nil
}

const configHeader = `# envseal configuration
# Managed by envseal CLI — edit via envseal commands
#
# [project]
#   name        — project name used in audit logs and CLI output
#   default_env — environment used when --env flag is omitted
#
# [environments.<name>]
#   vault  — path to encrypted vault file (relative to project root)
#   source — original .env file this environment maps to
#
# [recipients]
#   <name> = <age-public-key> — team members allowed to decrypt secrets

`

func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	// MkdirAll is a silent no-op when something already exists at the path —
	// including a pre-planted symlink. Refuse to write config.toml (the
	// recipient list, i.e. who can decrypt) through a redirected directory:
	// a save that lands outside the repo leaves the git-tracked config stale
	// while the command reports success.
	if err := fileutil.RequireRealDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("config directory: %w", err)
	}

	tc := tomlConfig{
		Project: tomlProject{
			Name:       c.ProjectName,
			DefaultEnv: c.Default,
		},
		Environments: c.Environments,
		Recipients:   c.Recipients,
	}

	var buf strings.Builder
	buf.WriteString(configHeader)

	if err := toml.NewEncoder(&buf).Encode(tc); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	return fileutil.AtomicWriteFile(
		path,
		[]byte(buf.String()),
		0600,
		".envseal-cfg-*",
	)
}

var validRecipientName = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.@-]*$`)

func ValidateRecipientName(name string) error {
	if !validRecipientName.MatchString(name) {
		return fmt.Errorf("recipient name %q contains invalid characters (allowed: a-z, A-Z, 0-9, _, ., @, -)", name)
	}
	if len(name) > 256 {
		return fmt.Errorf("recipient name %q exceeds maximum length of 256 characters", name)
	}
	return nil
}

// AddRecipient registers pubkey under name. If name already maps to a
// different key, this is refused unless force is true: silently replacing an
// existing recipient's key re-encrypts the vault so only the new key can
// decrypt it, permanently revoking whoever holds the private key matching
// the old one — including the vault owner themselves if name happens to be
// their own recipient entry (e.g. "default", the name init registers the
// owner's own key under). Re-registering the same key under its existing
// name is always allowed since it changes nothing.
func (c *Config) AddRecipient(name, pubkey string, force bool) error {
	if err := ValidateRecipientName(name); err != nil {
		return err
	}
	if _, err := age.ParseX25519Recipient(pubkey); err != nil {
		return fmt.Errorf("invalid age public key for %q: %w", name, err)
	}
	if c.Recipients == nil {
		c.Recipients = make(map[string]string)
	}
	if existing, exists := c.Recipients[name]; exists {
		if existing != pubkey && !force {
			return fmt.Errorf("recipient %q already exists with a different key — use --force to replace it (this revokes decrypt access for whoever holds the current private key, which may be your own if %q is your own recipient entry)", name, name)
		}
	} else if len(c.Recipients) >= maxRecipients {
		return fmt.Errorf("maximum of %d recipients reached", maxRecipients)
	}
	c.Recipients[name] = pubkey
	return nil
}

func (c *Config) RemoveRecipient(name string) error {
	if _, ok := c.Recipients[name]; !ok {
		return fmt.Errorf("recipient %q not found", name)
	}
	delete(c.Recipients, name)
	return nil
}

func (c *Config) GetEnvironment(name string) (Environment, error) {
	env, ok := c.Environments[name]
	if !ok {
		return Environment{}, fmt.Errorf("environment %q not found", name)
	}
	return env, nil
}

func (c *Config) CurrentEnvironment() Environment {
	return c.Environments[c.Default]
}

func (c *Config) SetDefault(env string) error {
	if err := ValidateEnvironmentName(env); err != nil {
		return err
	}
	if _, ok := c.Environments[env]; !ok {
		return fmt.Errorf("environment %q not found", env)
	}
	c.Default = env
	return nil
}

const maxEnvironmentNameLength = 64

func ValidateEnvironmentName(name string) error {
	if len(name) > maxEnvironmentNameLength {
		return fmt.Errorf("environment name %q exceeds maximum length of %d characters", name, maxEnvironmentNameLength)
	}
	if !validEnvName.MatchString(name) {
		return fmt.Errorf("environment name %q contains invalid characters (allowed: a-z, A-Z, 0-9, _, -)", name)
	}
	return nil
}

func (c *Config) AddEnvironment(name string) error {
	if err := ValidateEnvironmentName(name); err != nil {
		return err
	}
	if _, ok := c.Environments[name]; ok {
		return fmt.Errorf("environment %q already exists", name)
	}
	if len(c.Environments) >= maxEnvironments {
		return fmt.Errorf("maximum of %d environments reached", maxEnvironments)
	}
	c.Environments[name] = NewEnvironment(name)
	return nil
}

func (c *Config) EnvironmentNames() []string {
	names := make([]string, 0, len(c.Environments))
	for name := range c.Environments {
		names = append(names, name)
	}
	return names
}

func (c *Config) RecipientKeys() []string {
	keys := make([]string, 0, len(c.Recipients))
	for _, key := range c.Recipients {
		keys = append(keys, key)
	}
	return keys
}
