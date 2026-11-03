package envcheck

import (
	"strings"
	"testing"
)

func TestIsDangerous(t *testing.T) {
	for _, name := range DangerousVarNames() {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true", name)
		}
	}
}

func TestIsDangerous_CaseInsensitive(t *testing.T) {
	cases := []string{"path", "Path", "ld_preload", "Ld_Preload", "node_options"}
	for _, name := range cases {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true (case-insensitive)", name)
		}
	}
}

func TestIsDangerous_Safe(t *testing.T) {
	safe := []string{
		"DATABASE_URL", "API_KEY", "SECRET_TOKEN", "MY_VAR",
		"APP_PORT", "LOG_LEVEL", "",
	}
	for _, name := range safe {
		if IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = true, want false", name)
		}
	}
}

// TestIsDangerous_GitConfigInjection covers the reported bypass: git reads
// GIT_CONFIG_COUNT / GIT_CONFIG_KEY_<n> / GIT_CONFIG_VALUE_<n> and
// GIT_CONFIG_PARAMETERS exactly like `-c key=value`, so a vault entry set
// GIT_CONFIG_KEY_0=core.fsmonitor runs an attacker command on `git status`.
// The index <n> is unbounded, so no exact-name list can cover the family.
func TestIsDangerous_GitConfigInjection(t *testing.T) {
	cases := []string{
		"GIT_CONFIG_COUNT",
		"GIT_CONFIG_KEY_0",
		"GIT_CONFIG_VALUE_0",
		"GIT_CONFIG_KEY_17",
		"GIT_CONFIG_VALUE_4294967295",
		"GIT_CONFIG_PARAMETERS",
		"git_config_count",
		"Git_Config_Key_0",
		// Any other GIT_* name: git keeps adding environment knobs, so the
		// whole namespace is refused rather than chasing new ones.
		"GIT_SEQUENCE_EDITOR",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"GIT_INDEX_FILE",
		"GIT_TRACE",
		"GIT_TOKEN",
	}
	for _, name := range cases {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true", name)
		}
	}
}

// TestIsDangerous_ConfigFamilies covers tools that read *every* setting from
// a name pattern, where some setting names a program to execute.
func TestIsDangerous_ConfigFamilies(t *testing.T) {
	cases := []string{
		// npm/pnpm: npm_config_<option> sets any option (case-insensitive);
		// script-shell replaces the shell `npm run` executes.
		"NPM_CONFIG_SCRIPT_SHELL",
		"npm_config_script_shell",
		"NPM_CONFIG_NODE_OPTIONS",
		"NPM_CONFIG_GIT",
		// Yarn 2+: YARN_<SETTING> overrides any .yarnrc.yml setting;
		// yarnPath names the JavaScript file yarn executes.
		"YARN_YARN_PATH",
		"YARN_RC_FILENAME",
		// pip: PIP_<OPTION> sets any command-line option.
		"PIP_TRUSTED_HOST",
		"PIP_FIND_LINKS",
		// Cargo: CARGO_<KEY> sets any config key; runner/linker/rustc name
		// programs cargo executes.
		"CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
		"CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER",
		"CARGO_BUILD_RUSTC",
		"CARGO_REGISTRIES_FOO_CREDENTIAL_PROVIDER",
		"CARGO_CREDENTIAL_PROVIDER",
		"CARGO_REGISTRIES_TOKEN",
		"CARGO_REGISTRIES__TOKEN",
		// rustup: RUSTUP_TOOLCHAIN may be a path to a custom toolchain.
		"RUSTUP_TOOLCHAIN",
		"RUSTUP_HOME",
		// cgo: CGO_<LANG>FLAGS reach the C compiler (e.g. -fplugin=).
		"CGO_CPPFLAGS",
		"CGO_CXXFLAGS",
		"CGO_FFLAGS",
		// Dynamic loaders.
		"LD_BIND_NOW",
		"LD_ORIGIN_PATH",
		"DYLD_PRINT_TO_FILE",
		"DYLD_ROOT_PATH",
	}
	for _, name := range cases {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true", name)
		}
	}
}

// TestIsDangerous_BuildToolPrograms covers single variables that name a
// program (or flags that load one) run by go, make, cargo, node-gyp, pip.
func TestIsDangerous_BuildToolPrograms(t *testing.T) {
	cases := []string{
		"GOCACHEPROG", "GOAUTH", "GOCACHE",
		"CC", "CXX", "CPP", "AR", "PKG_CONFIG",
		"CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS",
		"RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS",
	}
	for _, name := range cases {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true", name)
		}
	}
}

// TestIsDangerous_CargoRegistryTokensAllowed: registry tokens are ordinary
// secrets (crates.io publish tokens in CI) and configure no program.
func TestIsDangerous_CargoRegistryTokensAllowed(t *testing.T) {
	cases := []string{
		"CARGO_REGISTRY_TOKEN",
		"cargo_registry_token",
		"CARGO_REGISTRIES_MY_REGISTRY_TOKEN",
		"CARGO_REGISTRIES_FOO_TOKEN",
	}
	for _, name := range cases {
		if IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = true, want false", name)
		}
	}
}

// TestIsDangerous_SafeLookalikes: names that share letters with a dangerous
// prefix but are not in its namespace must stay usable.
func TestIsDangerous_SafeLookalikes(t *testing.T) {
	safe := []string{
		"GITHUB_TOKEN", "GITLAB_TOKEN", "GITEA_TOKEN", "DIGIT_COUNT", "LEGIT_KEY",
		"NPM_TOKEN", "NPM_CONFIG", "YARNISH", "PIPELINE_ID", "PIPE_NAME",
		"CARGOX", "LDAP_URL", "LDAP_PASSWORD", "OLD_PRELOAD",
		"CC_NUMBER", "ARGO_TOKEN", "RUST_LOG", "RUST_BACKTRACE",
		"NODE_ENV", "GO_ENV", "CGOX", "DYLDX",
	}
	for _, name := range safe {
		if IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = true, want false", name)
		}
	}
}

// TestDangerousPrefixes_MatchWholeNamespace: every prefix ends in "_" so that
// "GIT_" does not swallow GITHUB_TOKEN, and every prefix is refused.
func TestDangerousPrefixes_MatchWholeNamespace(t *testing.T) {
	prefixes := DangerousPrefixes()
	if len(prefixes) == 0 {
		t.Fatal("DangerousPrefixes() is empty")
	}
	for _, p := range prefixes {
		if !strings.HasSuffix(p, "_") {
			t.Errorf("prefix %q must end with \"_\"", p)
		}
		if p != strings.ToUpper(p) {
			t.Errorf("prefix %q must be upper-case (IsDangerous upper-cases names)", p)
		}
		if !IsDangerous(p + "X") {
			t.Errorf("IsDangerous(%q) = false, want true", p+"X")
		}
	}
}

// TestDangerousVarNames_NotShadowedByPrefix keeps the exact list free of
// names a prefix already refuses, so the two lists cannot drift apart.
func TestDangerousVarNames_NotShadowedByPrefix(t *testing.T) {
	for _, name := range DangerousVarNames() {
		for _, p := range DangerousPrefixes() {
			if strings.HasPrefix(name, p) {
				t.Errorf("exact name %q is already covered by prefix %q, remove it", name, p)
			}
		}
	}
}

// TestDangerousPrefixes_ReturnsCopy: callers must not be able to weaken the
// check by mutating the returned slice.
func TestDangerousPrefixes_ReturnsCopy(t *testing.T) {
	got := DangerousPrefixes()
	got[0] = "SAFE_"
	if !IsDangerous("GIT_CONFIG_COUNT") || IsDangerous("SAFE_X") {
		t.Error("mutating DangerousPrefixes() result changed IsDangerous")
	}
}

// TestIsDangerous_YarnAuthAllowed: Yarn's registry credentials are ordinary
// CI secrets and configure no program; the registry they are sent to
// (YARN_NPM_REGISTRY_SERVER) stays refused.
func TestIsDangerous_YarnAuthAllowed(t *testing.T) {
	for _, name := range []string{"YARN_NPM_AUTH_TOKEN", "yarn_npm_auth_token", "YARN_NPM_AUTH_IDENT"} {
		if IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = true, want false", name)
		}
	}
	for _, name := range []string{"YARN_NPM_REGISTRY_SERVER", "YARN_NPM_AUTH_TOKEN_X", "YARN_NPM_ALWAYS_AUTH"} {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true", name)
		}
	}
}

// TestAllowedUnderPrefix_UnderDangerousPrefix: an exception only makes sense
// for a name a prefix would otherwise refuse, and must never cover a name on
// the exact list.
func TestAllowedUnderPrefix_UnderDangerousPrefix(t *testing.T) {
	for name := range allowedUnderPrefix {
		if name != strings.ToUpper(name) {
			t.Errorf("credential %q must be upper-case", name)
		}
		if dangerousVars[name] {
			t.Errorf("credential %q is also on the exact dangerous list", name)
		}
		covered := false
		for _, p := range dangerousPrefixes {
			covered = covered || strings.HasPrefix(name, p)
		}
		if !covered {
			t.Errorf("credential %q is under no dangerous prefix, so the exception is dead code", name)
		}
	}
}

// TestIsDangerous_CargoRegistryDestinationsRefused: only the token is an
// exception; where it is sent and how it is produced stay refused.
func TestIsDangerous_CargoRegistryDestinationsRefused(t *testing.T) {
	for _, name := range []string{
		"CARGO_REGISTRIES_FOO_INDEX",
		"CARGO_REGISTRY_INDEX",
		"CARGO_REGISTRY_CREDENTIAL_PROVIDER",
		"CARGO_REGISTRIES_FOO_TOKEN_X",
		"CARGO_REGISTRIES_FOO_CREDENTIAL_PROVIDER",
	} {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true", name)
		}
	}
}

// TestIsDangerous_FormerExactNamesStillRefused: these names were on the exact
// list before the prefix families replaced them; moving them must not make
// any of them injectable.
func TestIsDangerous_FormerExactNamesStillRefused(t *testing.T) {
	former := []string{
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_PROFILE_OUTPUT", "LD_DEBUG_OUTPUT",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FALLBACK_FRAMEWORK_PATH",
		"GIT_ASKPASS", "CGO_CFLAGS", "CGO_LDFLAGS",
		"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE", "PIP_TARGET",
		"NPM_CONFIG_REGISTRY", "NPM_CONFIG_PREFIX", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG",
		"CARGO_HOME", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
		"GIT_SSH", "GIT_PAGER", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_EDITOR",
		"GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_TEMPLATE_DIR", "GIT_PROXY_COMMAND",
		"GIT_EXEC_PATH", "GIT_DIR", "GIT_WORK_TREE",
		"BUNDLE_GEMFILE", "BUNDLE_PATH",
		"XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "XDG_DATA_HOME",
	}
	if len(former) != 41 {
		t.Fatalf("expected the 41 names moved to prefixes, got %d", len(former))
	}
	for _, name := range former {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false: moving it to a prefix weakened the check", name)
		}
	}
}

// TestIsDangerous_ReviewFindings covers the second review pass: single names
// and namespaces where a name plus a value is enough to run code or send
// credentials elsewhere, with no planted file needed.
func TestIsDangerous_ReviewFindings(t *testing.T) {
	cases := []string{
		// GNU make: parsed like MAKEFLAGS; built-in program variables.
		"GNUMAKEFLAGS", "RM", "LD", "AS", "YACC", "LEX", "FC",
		// cc-rs (cargo build scripts): host/target compiler overrides.
		"TARGET_CC", "TARGET_CXX", "TARGET_AR", "TARGET_CFLAGS", "TARGET_CXXFLAGS",
		"HOST_CC", "HOST_CXX", "HOST_AR", "HOST_CFLAGS", "HOST_CXXFLAGS",
		"CC_X86_64_UNKNOWN_LINUX_GNU", "cc_x86_64_unknown_linux_gnu", "CXX_AARCH64_APPLE_DARWIN",
		"AR_I686_PC_WINDOWS_MSVC", "CFLAGS_WASM32_UNKNOWN_UNKNOWN", "CXXFLAGS_ARMV7_UNKNOWN_LINUX_GNUEABIHF",
		"CC_RISCV64GC_UNKNOWN_LINUX_GNU", "CC_THUMBV7EM_NONE_EABIHF",
		// Build helpers that run a named program.
		"PYTHON", "PROTOC", "CMAKE", "PYO3_PYTHON",
		// kubectl.
		"KUBE_EDITOR", "KUBECTL_EXTERNAL_DIFF",
		// JVM build tools.
		"JAVA_OPTS", "MAVEN_ARGS",
		// node REPL.
		"NODE_REPL_EXTERNAL_MODULE",
		// Credential exfiltration by redirecting the endpoint.
		"TWINE_REPOSITORY_URL", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3",
		// Interactive shell prompts expand $(...).
		"PS0", "PS1", "PS2", "PS3",
		// Whole configuration namespaces.
		"BUNDLE_MIRROR__RUBYGEMS__ORG", "BUNDLE_APP_CONFIG", "BUNDLE_BUILD__NOKOGIRI",
		"UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_PYTHON",
		"POETRY_REPOSITORIES_X_URL", "PDM_PYPI_URL", "PIPENV_PYPI_MIRROR",
		"COREPACK_NPM_REGISTRY", "COREPACK_INTEGRITY_KEYS",
	}
	for _, name := range cases {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true", name)
		}
	}
}

// TestIsDangerous_TargetSuffixLookalikes: the cc-rs <TOOL>_<target> rule must
// only fire for a Rust target architecture, not for ordinary app names.
func TestIsDangerous_TargetSuffixLookalikes(t *testing.T) {
	safe := []string{
		"CC_NUMBER", "CC_EMAIL", "CC_LIST", "AR_INVOICE_ID", "CXX_STANDARD_NOTE",
		"CFLAGS_NOTE", "CC_ARMORED", "TARGET_ENV", "TARGET_URL", "HOST_NAME", "HOST_URL",
		"PYTHON_VERSION_NOTE", "AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
		"TWINE_USERNAME", "TWINE_PASSWORD", "PROMPT", "BUNDLER_X",
	}
	for _, name := range safe {
		if IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = true, want false", name)
		}
	}
}

// TestIsDangerous_SecondPass covers the second edge-case pass.
func TestIsDangerous_SecondPass(t *testing.T) {
	cases := []string{
		// node-gyp runs $MAKE and $NODE_GYP_FORCE_PYTHON during npm install.
		"MAKE", "NODE_GYP_FORCE_PYTHON",
		// cc-rs: ranlib/ar flags (GNU ar --plugin loads a library), pkg-config
		// crate: TARGET_/HOST_/per-target PKG_CONFIG programs.
		"RANLIB", "ARFLAGS", "TARGET_RANLIB", "HOST_RANLIB", "TARGET_ARFLAGS", "HOST_ARFLAGS",
		"TARGET_PKG_CONFIG", "HOST_PKG_CONFIG",
		"ARFLAGS_X86_64_UNKNOWN_LINUX_GNU", "PKG_CONFIG_AARCH64_UNKNOWN_LINUX_GNU",
		"CC_AMDGCN_AMD_AMDHSA",
		// Python/Perl gadgets.
		"PYTHONWARNINGS", "PYTHONHTTPSVERIFY", "PERL5DB",
		// Ant passes ANT_OPTS to the JVM like JAVA_OPTS.
		"ANT_OPTS",
		// less: +<cmd> runs a command at startup (! is shell escape); lesskey
		// content/files bind keys to commands; LESSEDIT is the editor command.
		"LESS", "LESSKEY", "LESSKEYIN", "LESSKEY_CONTENT", "LESSEDIT",
		// Remote-shell helpers run as commands by rsync, cvs, svn, hg.
		"RSYNC_RSH", "RSYNC_CONNECT_PROG", "RSYNC_PROXY", "CVS_RSH", "SVN_SSH", "HGEDITOR", "HGMERGE",
		// Daemon/API endpoint redirection that hands over build contexts,
		// mounted secrets or a service-account token.
		"BUILDKIT_HOST", "CONTAINER_HOST", "CONTAINER_CONNECTION",
		"KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_EC2_METADATA_SERVICE_ENDPOINT",
		"GRPC_PROXY", "JSR_URL",
		// TLS verification switches.
		"NODE_TLS_REJECT_UNAUTHORIZED",
		// Electron binaries (VS Code `code`) act as plain node.
		"ELECTRON_RUN_AS_NODE",
		// PowerShell honours this as the session execution policy.
		"PSEXECUTIONPOLICYPREFERENCE", "PSExecutionPolicyPreference",
		// Windows folders tools read config/binaries from (Git for Windows
		// reads its system config under PROGRAMDATA).
		"PROGRAMDATA", "PROGRAMFILES", "PROGRAMW6432", "COMMONPROGRAMFILES", "ALLUSERSPROFILE",
		// AIX / HP-UX loader paths; OpenSSL provider/engine directories.
		"LIBPATH", "SHLIB_PATH", "OPENSSL_MODULES", "OPENSSL_ENGINES",
		// Go module mode / VCS policy downgrades.
		"GO111MODULE", "GOVCS",
		// Whole namespaces: XDG dirs, Terraform CLI args, Ansible config,
		// gcloud config (CLOUDSDK_PYTHON runs a program), Bun config, Helm.
		"XDG_CONFIG_DIRS", "XDG_DATA_DIRS", "XDG_CACHE_HOME", "XDG_STATE_HOME",
		"TF_CLI_ARGS", "TF_CLI_ARGS_APPLY", "TF_CLI_ARGS_PLAN",
		"ANSIBLE_SSH_ARGS", "ANSIBLE_SSH_EXECUTABLE", "ANSIBLE_BECOME_EXE",
		"CLOUDSDK_PYTHON", "CLOUDSDK_API_ENDPOINT_OVERRIDES_STORAGE",
		"BUN_CONFIG_REGISTRY", "HELM_KUBEAPISERVER", "HELM_PLUGINS",
	}
	for _, name := range cases {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true", name)
		}
	}
}

// TestIsDangerous_SecondPassAllowed: runtime knobs and credentials that live
// under a refused namespace but configure no program or destination.
func TestIsDangerous_SecondPassAllowed(t *testing.T) {
	safe := []string{
		// libuv (Node.js) runtime knobs commonly kept in an app's .env.
		"UV_THREADPOOL_SIZE", "UV_USE_IO_URING",
		// Credentials whose destination stays refused.
		"BUN_CONFIG_TOKEN", "HELM_KUBETOKEN",
		// Lookalikes.
		"LESSON_ID", "LESS_X", "MAKER_ID", "HELMET_KEY", "XDGX", "TF_VAR_REGION",
		"TF_TOKEN_APP_TERRAFORM_IO", "ANSIBLEX", "KUBERNETES_NAMESPACE",
		"DOCKER_PASSWORD", "AZURE_CLIENT_SECRET",
	}
	for _, name := range safe {
		if IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = true, want false", name)
		}
	}
}
