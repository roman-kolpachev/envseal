package envcheck

import "strings"

var dangerousVars = map[string]bool{
	// Library injection: every LD_* and DYLD_* name is refused by prefix
	// (see dangerousPrefixes).

	// Shell/system
	"COMSPEC":        true,
	"WINDIR":         true,
	"SYSTEMROOT":     true,
	"PATH":           true,
	"CDPATH":         true,
	"IFS":            true,
	"ENV":            true,
	"BASH_ENV":       true,
	"SHELLOPTS":      true,
	"BASHOPTS":       true,
	"ZDOTDIR":        true,
	"INPUTRC":        true,
	"PROMPT_COMMAND": true,
	"PS4":            true,
	"SHELL":          true,
	"HOME":           true,
	// Windows analogues of HOME: redirecting the profile/appdata roots makes
	// shells, git, npm, PowerShell ($PROFILE lives under Documents via
	// USERPROFILE) and countless other tools load attacker-controlled config
	// and startup scripts — the same code-execution primitive as HOME above.
	"USERPROFILE":  true,
	"HOMEDRIVE":    true,
	"HOMEPATH":     true,
	"APPDATA":      true,
	"LOCALAPPDATA": true,

	// Command execution via editor/pager invocation
	"EDITOR":    true,
	"VISUAL":    true,
	"PAGER":     true,
	"MANPAGER":  true,
	"BROWSER":   true,
	"LESSOPEN":  true,
	"LESSCLOSE": true,

	// Command execution via askpass helpers
	"SSH_ASKPASS":  true,
	"SUDO_ASKPASS": true,

	// Runtime code injection
	"NODE_OPTIONS":        true,
	"NODE_PATH":           true,
	"NODE_EXTRA_CA_CERTS": true,
	"PYTHONPATH":          true,
	"PYTHONSTARTUP":       true,
	"PYTHONHOME":          true,
	"PYTHONBREAKPOINT":    true,
	// PYTHONUSERBASE redirects the user site-packages directory, so an
	// attacker-controlled path lets arbitrary modules shadow stdlib imports.
	"PYTHONUSERBASE":       true,
	"RUBYLIB":              true,
	"RUBYOPT":              true,
	"GEM_HOME":             true,
	"GEM_PATH":             true,
	"PERL5LIB":             true,
	"PERL5OPT":             true,
	"CLASSPATH":            true,
	"DOTNET_ROOT":          true,
	"DOTNET_STARTUP_HOOKS": true,
	"LUA_PATH":             true,
	"LUA_CPATH":            true,
	"PHPRC":                true,
	"PHP_INI_SCAN_DIR":     true,

	// Go build injection (CGO_* is refused by prefix, see dangerousPrefixes)
	"GOFLAGS": true,
	// GOCACHEPROG names a program the go command starts as its build cache;
	// GOAUTH can name a command go runs to fetch credentials; GOCACHE pointed
	// at a planted directory serves attacker-built objects to `go build`.
	"GOCACHEPROG":  true,
	"GOAUTH":       true,
	"GOCACHE":      true,
	"GOPROXY":      true,
	"GONOSUMCHECK": true,
	"GONOSUMDB":    true,
	"GOINSECURE":   true,
	"GOTOOLCHAIN":  true,
	"GOPATH":       true,
	"GOROOT":       true,
	"GOTMPDIR":     true,
	"GOMODCACHE":   true,
	// GODEBUG toggles Go runtime security behaviours (TLS cipher/version
	// re-enablement, x509 leniency, fips140 mode) in every Go child process.
	"GODEBUG": true,
	// GOENV names the file the go command reads its environment config from —
	// an attacker-controlled file there sets GOFLAGS, GOPROXY, GOTOOLCHAIN and
	// every other variable this list blocks individually, in one shot.
	"GOENV": true,
	// GOSUMDB redirects (or with "off" disables) module checksum verification;
	// GOPRIVATE/GONOPROXY/GONOSUMDB-style patterns exempt attacker-chosen
	// module paths from proxy and sumdb verification entirely.
	"GOSUMDB":   true,
	"GOPRIVATE": true,
	"GONOPROXY": true,

	// Package manager redirection. npm (NPM_CONFIG_*), Yarn (YARN_*), pip
	// (PIP_*) and Cargo (CARGO_*) are refused by prefix (see dangerousPrefixes).
	"COMPOSER_HOME": true,

	// TLS/proxy interception
	"SSL_CERT_FILE":      true,
	"SSL_CERT_DIR":       true,
	"CURL_CA_BUNDLE":     true,
	"REQUESTS_CA_BUNDLE": true,
	"OPENSSL_CONF":       true,
	"HTTP_PROXY":         true,
	"HTTPS_PROXY":        true,

	// XDG config/runtime redirection: every XDG_* name is refused by prefix
	// (see dangerousPrefixes).

	// Temp directory hijacking
	"TMPDIR": true,
	"TMP":    true,
	"TEMP":   true,

	// Git command/config injection: every GIT_* name is refused by prefix
	// (see dangerousPrefixes).

	// Infrastructure tool redirection
	"DOCKER_HOST":                    true,
	"DOCKER_CONFIG":                  true,
	"KUBECONFIG":                     true,
	"AWS_SHARED_CREDENTIALS_FILE":    true,
	"AWS_CONFIG_FILE":                true,
	"AWS_CA_BUNDLE":                  true,
	"GOOGLE_APPLICATION_CREDENTIALS": true,
	"AZURE_CONFIG_DIR":               true,

	// envseal internal variables
	"ENVSEAL_KEY":     true,
	"ENVSEAL_SECRETS": true,

	// Additional proxy interception
	"NO_PROXY":  true,
	"ALL_PROXY": true,
	"FTP_PROXY": true,

	// JVM code injection via -javaagent
	"JAVA_TOOL_OPTIONS": true,
	"JDK_JAVA_OPTIONS":  true,
	"_JAVA_OPTIONS":     true,
	"MAVEN_OPTS":        true,
	"GRADLE_OPTS":       true,
	"SBT_OPTS":          true,

	// glibc code injection via iconv/gconv module loading
	"GCONV_PATH": true,
	// glibc tunables: exploited by CVE-2023-4911 ("Looney Tunables") for local
	// privilege escalation via ld.so; also disables safe-mode hardening.
	"GLIBC_TUNABLES": true,
	// glibc locale/message-catalog path redirection
	"LOCPATH": true,
	"NLSPATH": true,

	// DNS resolution hijacking (glibc resolver)
	"HOSTALIASES":      true,
	"RESOLV_HOST_CONF": true,

	// Perl library injection (PERLLIB complements PERL5LIB above)
	"PERLLIB": true,

	// Windows command resolution and PowerShell module injection
	"PATHEXT":      true,
	"PSMODULEPATH": true,

	// Rust/Cargo build-time arbitrary command execution: these name a binary
	// that cargo/rustc invokes in place of (or wrapping) the real compiler,
	// or pass flags such as `-C linker=<program>` to every rustc invocation.
	// CARGO_* and RUSTUP_* are refused by prefix (see dangerousPrefixes).
	"RUSTC_WRAPPER":           true,
	"RUSTC_WORKSPACE_WRAPPER": true,
	"RUSTC":                   true,
	"RUSTDOC":                 true,
	"RUSTFLAGS":               true,
	"RUSTDOCFLAGS":            true,

	// C toolchain: go (cgo), make, cargo build scripts, node-gyp and pip
	// source builds run $CC/$CXX/$CPP/$AR/$PKG_CONFIG as programs, and the
	// *FLAGS variables reach the compiler/linker command line, where
	// -fplugin=, -wrapper or -B load attacker code. MAKEFLAGS can override
	// SHELL and any other make variable.
	"CC":         true,
	"CXX":        true,
	"CPP":        true,
	"AR":         true,
	"PKG_CONFIG": true,
	"CFLAGS":     true,
	"CXXFLAGS":   true,
	"CPPFLAGS":   true,
	"LDFLAGS":    true,
	"MAKEFLAGS":  true,
	// GNU make parses GNUMAKEFLAGS exactly like MAKEFLAGS, and the
	// environment overrides make's built-in program variables ($(RM) runs in
	// nearly every `make clean`).
	"GNUMAKEFLAGS": true,
	"RM":           true,
	"LD":           true,
	"AS":           true,
	"YACC":         true,
	"LEX":          true,
	"FC":           true,
	// cc-rs (the cc crate used by cargo build scripts) also reads
	// HOST_/TARGET_ variants; per-target <TOOL>_<target> names are matched
	// by isTargetToolchainVar.
	"TARGET_CC":       true,
	"TARGET_CXX":      true,
	"TARGET_AR":       true,
	"TARGET_CFLAGS":   true,
	"TARGET_CXXFLAGS": true,
	"HOST_CC":         true,
	"HOST_CXX":        true,
	"HOST_AR":         true,
	"HOST_CFLAGS":     true,
	"HOST_CXXFLAGS":   true,
	// Programs build helpers run: node-gyp ($PYTHON), prost-build ($PROTOC),
	// the cmake crate ($CMAKE), PyO3 ($PYO3_PYTHON).
	"PYTHON":      true,
	"PROTOC":      true,
	"CMAKE":       true,
	"PYO3_PYTHON": true,

	// kubectl runs KUBE_EDITOR on `kubectl edit` and KUBECTL_EXTERNAL_DIFF on
	// `kubectl diff`.
	"KUBE_EDITOR":           true,
	"KUBECTL_EXTERNAL_DIFF": true,
	// JVM options for gradlew/mvn scripts (-XX:OnOutOfMemoryError=<cmd>,
	// -javaagent:) and extra Maven arguments.
	"JAVA_OPTS":  true,
	"MAVEN_ARGS": true,
	// node's REPL loads this module instead of the built-in REPL.
	"NODE_REPL_EXTERNAL_MODULE": true,
	// Endpoint redirection that sends credentials elsewhere: `twine upload`
	// sends TWINE_PASSWORD to TWINE_REPOSITORY_URL; AWS CLI/SDKs send signed
	// requests and payloads to AWS_ENDPOINT_URL (AWS_ENDPOINT_URL_<SERVICE>
	// is refused by prefix).
	"TWINE_REPOSITORY_URL": true,
	"AWS_ENDPOINT_URL":     true,
	// node-gyp (npm install of native addons) runs $MAKE and
	// $NODE_GYP_FORCE_PYTHON.
	"MAKE":                  true,
	"NODE_GYP_FORCE_PYTHON": true,
	// cc-rs: ranlib and ar flags (GNU ar --plugin loads a library); the
	// pkg-config crate runs TARGET_/HOST_ PKG_CONFIG programs.
	"RANLIB":            true,
	"ARFLAGS":           true,
	"TARGET_RANLIB":     true,
	"HOST_RANLIB":       true,
	"TARGET_ARFLAGS":    true,
	"HOST_ARFLAGS":      true,
	"TARGET_PKG_CONFIG": true,
	"HOST_PKG_CONFIG":   true,
	// Python warnings filters import the named module (a known gadget
	// together with BROWSER); PYTHONHTTPSVERIFY=0 disables certificate
	// checks on some builds; PERL5DB is code run by `perl -d`.
	"PYTHONWARNINGS":    true,
	"PYTHONHTTPSVERIFY": true,
	"PERL5DB":           true,
	// Ant passes ANT_OPTS to the JVM, like JAVA_OPTS.
	"ANT_OPTS": true,
	// less, the default git/man pager: LESS="+<cmd>" runs a command at
	// startup (! is its shell escape); lesskey files/content bind keys to
	// commands; LESSEDIT is the editor command line.
	"LESS":            true,
	"LESSKEY":         true,
	"LESSKEYIN":       true,
	"LESSKEY_CONTENT": true,
	"LESSEDIT":        true,
	// Remote-shell helpers run as commands by rsync, cvs, svn and hg.
	"RSYNC_RSH":          true,
	"RSYNC_CONNECT_PROG": true,
	"RSYNC_PROXY":        true,
	"CVS_RSH":            true,
	"SVN_SSH":            true,
	"HGEDITOR":           true,
	"HGMERGE":            true,
	// Daemon/API endpoints that would receive a build context, mounted build
	// secrets, or a pod's service-account token (client-go in-cluster config).
	"BUILDKIT_HOST":                      true,
	"CONTAINER_HOST":                     true,
	"CONTAINER_CONNECTION":               true,
	"KUBERNETES_SERVICE_HOST":            true,
	"KUBERNETES_SERVICE_PORT":            true,
	"AWS_CONTAINER_CREDENTIALS_FULL_URI": true,
	"AWS_EC2_METADATA_SERVICE_ENDPOINT":  true,
	"GRPC_PROXY":                         true,
	// Deno fetches jsr: modules from JSR_URL and runs them.
	"JSR_URL": true,
	// Disables TLS certificate verification in every Node.js process.
	"NODE_TLS_REJECT_UNAUTHORIZED": true,
	// Electron binaries (e.g. VS Code's `code`) behave as plain node.
	"ELECTRON_RUN_AS_NODE": true,
	// PowerShell takes this as the session's execution policy.
	"PSEXECUTIONPOLICYPREFERENCE": true,
	// Windows folders tools read config and binaries from (Git for Windows
	// reads its system config under PROGRAMDATA).
	"PROGRAMDATA":        true,
	"PROGRAMFILES":       true,
	"PROGRAMW6432":       true,
	"COMMONPROGRAMFILES": true,
	"ALLUSERSPROFILE":    true,
	// AIX and HP-UX loader search paths; OpenSSL provider/engine directories.
	"LIBPATH":         true,
	"SHLIB_PATH":      true,
	"OPENSSL_MODULES": true,
	"OPENSSL_ENGINES": true,
	// GO111MODULE=off drops module checksum verification; GOVCS widens which
	// version-control tools go may run for downloads.
	"GO111MODULE": true,
	"GOVCS":       true,
	// Terraform adds TF_CLI_ARGS (and TF_CLI_ARGS_<command>, by prefix) to
	// every command line, e.g. apply -auto-approve.
	"TF_CLI_ARGS": true,

	// Interactive shells expand $(...) in prompt strings.
	"PS0": true,
	"PS1": true,
	"PS2": true,
	"PS3": true,

	// TLS session-key logging: any TLS stack honoring SSLKEYLOGFILE writes
	// the session keys for every connection to an attacker-chosen path,
	// enabling passive decryption of captured traffic.
	"SSLKEYLOGFILE": true,

	// .NET CLR profiler injection: a profiler DLL named by these variables
	// is loaded into every .NET process at startup with full code execution.
	"COR_ENABLE_PROFILING":     true,
	"COR_PROFILER":             true,
	"COR_PROFILER_PATH":        true,
	"CORECLR_ENABLE_PROFILING": true,
	"CORECLR_PROFILER":         true,
	"CORECLR_PROFILER_PATH":    true,
	"DOTNET_ADDITIONAL_DEPS":   true,
}

// dangerousPrefixes are whole namespaces a tool reads as configuration by
// pattern rather than by a fixed set of names, so an exact-name list cannot
// cover them: git turns GIT_CONFIG_COUNT / GIT_CONFIG_KEY_<n> /
// GIT_CONFIG_VALUE_<n> (and GIT_CONFIG_PARAMETERS) into `-c key=value`, and
// npm, Yarn, pip and Cargo map NPM_CONFIG_<option>, YARN_<setting>,
// PIP_<option> and CARGO_<key> onto any of their settings. Several of them
// name a program to execute (core.fsmonitor, script-shell, yarnPath,
// target.<triple>.runner). Each prefix ends in "_" so that, for example,
// GITHUB_TOKEN is not caught by GIT_.
var dangerousPrefixes = []string{
	// git: any GIT_*. This covers config injection and the many GIT_* knobs
	// git keeps adding (GIT_SSH_COMMAND, GIT_EXTERNAL_DIFF, GIT_SEQUENCE_EDITOR, ...).
	"GIT_",
	// glibc ld.so and macOS dyld: LD_PRELOAD, LD_AUDIT, DYLD_INSERT_LIBRARIES
	// and the rest of both loader namespaces.
	"LD_",
	"DYLD_",
	// cgo: CGO_CFLAGS, CGO_CPPFLAGS, CGO_CXXFLAGS, CGO_FFLAGS, CGO_LDFLAGS.
	"CGO_",
	// npm and pnpm read npm_config_<option> case-insensitively for every
	// option; script-shell replaces the shell `npm run` executes.
	"NPM_CONFIG_",
	// Yarn 2+ reads YARN_<SETTING> for every .yarnrc.yml setting; yarnPath
	// names the JavaScript file yarn executes. Auth credentials are allowed,
	// see isAllowedUnderPrefix.
	"YARN_",
	// pip reads PIP_<OPTION> for every command-line option (index URLs,
	// find-links, trusted hosts, config file).
	"PIP_",
	// Cargo reads CARGO_<KEY> for every config key (build.rustc,
	// target.<triple>.runner/linker, credential providers, aliases).
	// Registry tokens are allowed, see isAllowedUnderPrefix.
	"CARGO_",
	// rustup: RUSTUP_TOOLCHAIN may be a path to a toolchain whose binaries
	// cargo and rustc then run; RUSTUP_HOME relocates every toolchain.
	"RUSTUP_",
	// Bundler reads BUNDLE_<SETTING> for every setting: mirrors
	// (BUNDLE_MIRROR__<HOST>), per-gem build flags, BUNDLE_APP_CONFIG.
	"BUNDLE_",
	// Python package managers with the same index/interpreter redirection
	// as PIP_: uv, Poetry, PDM, Pipenv.
	"UV_",
	"POETRY_",
	"PDM_",
	"PIPENV_",
	// Corepack downloads and runs yarn/pnpm from COREPACK_NPM_REGISTRY and
	// can be told to skip signature checks (COREPACK_INTEGRITY_KEYS).
	"COREPACK_",
	// AWS_ENDPOINT_URL_<SERVICE>: per-service endpoint redirection.
	"AWS_ENDPOINT_URL_",
	// XDG base directories: where git, pip, npm and most CLI tools read
	// their config from.
	"XDG_",
	// TF_CLI_ARGS_<command>: extra arguments for one terraform command.
	"TF_CLI_ARGS_",
	// Ansible reads ANSIBLE_<SETTING> for every ansible.cfg setting,
	// including ssh_args (-o ProxyCommand=...) and the executables it runs.
	"ANSIBLE_",
	// gcloud reads CLOUDSDK_<SECTION>_<PROPERTY> for every property:
	// CLOUDSDK_PYTHON is the interpreter it runs, API endpoint overrides
	// redirect authenticated requests.
	"CLOUDSDK_",
	// Bun reads BUN_CONFIG_* (registry and install settings).
	"BUN_CONFIG_",
	// Helm: API server, CA file, plugin and registry config locations.
	"HELM_",
}

// targetToolchainVars are the cc-rs variables that also come in a
// per-target form, <TOOL>_<target triple with - and . as _>.
var targetToolchainVars = []string{"CC_", "CXX_", "AR_", "ARFLAGS_", "CFLAGS_", "CXXFLAGS_", "RANLIB_", "PKG_CONFIG_"}

// rustTargetArchs are the first components of Rust target triples. A name
// is only a cc-rs per-target variable when one of these follows the tool, so
// CC_NUMBER or AR_INVOICE_ID stay usable.
var rustTargetArchs = []string{
	"AARCH64", "AMDGCN", "ARM64", "ARMEB", "ARMV", "ARM_", "AVR", "BPFEB", "BPFEL", "CSKY",
	"HEXAGON", "I386", "I586", "I686", "LOONGARCH", "M68K", "MIPS", "MSP430",
	"NVPTX", "POWERPC", "RISCV", "S390X", "SPARC", "THUMBV", "WASM32", "WASM64",
	"X86_64", "XTENSA",
}

// isTargetToolchainVar reports whether an upper-cased name is a cc-rs
// per-target compiler/flags variable such as CC_X86_64_UNKNOWN_LINUX_GNU.
func isTargetToolchainVar(upper string) bool {
	for _, tool := range targetToolchainVars {
		rest, ok := strings.CutPrefix(upper, tool)
		if !ok {
			continue
		}
		for _, arch := range rustTargetArchs {
			if strings.HasPrefix(rest, arch) {
				return true
			}
		}
	}
	return false
}

// allowedUnderPrefix are names under a dangerous prefix that configure no
// program or destination, so they stay usable: credentials (typically CI
// publish tokens) whose destination stays refused (YARN_NPM_REGISTRY_SERVER,
// CARGO_REGISTRIES_<NAME>_INDEX, BUN_CONFIG_REGISTRY, HELM_KUBEAPISERVER),
// and libuv runtime knobs that share the UV_ prefix with the uv tool and are
// common in Node.js apps' .env files.
var allowedUnderPrefix = map[string]bool{
	"CARGO_REGISTRY_TOKEN": true,
	"YARN_NPM_AUTH_TOKEN":  true,
	"YARN_NPM_AUTH_IDENT":  true,
	"BUN_CONFIG_TOKEN":     true,
	"HELM_KUBETOKEN":       true,
	"UV_THREADPOOL_SIZE":   true,
	"UV_USE_IO_URING":      true,
}

// isAllowedUnderPrefix reports whether an upper-cased name is one of
// allowedUnderPrefix or a CARGO_REGISTRIES_<NAME>_TOKEN.
func isAllowedUnderPrefix(upper string) bool {
	if allowedUnderPrefix[upper] {
		return true
	}
	const prefix, suffix = "CARGO_REGISTRIES_", "_TOKEN"
	// Slice rather than Trim: in CARGO_REGISTRIES_TOKEN the prefix and suffix
	// overlap, and that name (no registry) must not count as a token.
	if len(upper) <= len(prefix)+len(suffix) ||
		!strings.HasPrefix(upper, prefix) || !strings.HasSuffix(upper, suffix) {
		return false
	}
	registry := upper[len(prefix) : len(upper)-len(suffix)]
	return !strings.HasPrefix(registry, "_") && !strings.HasSuffix(registry, "_")
}

// IsDangerous reports whether injecting a variable with this name into a
// child process could let whoever controls its value run code or redirect a
// tool. The check is case-insensitive: Windows environment names are, and
// npm reads npm_config_* in any case.
func IsDangerous(name string) bool {
	upper := strings.ToUpper(name)
	if dangerousVars[upper] || isTargetToolchainVar(upper) {
		return true
	}
	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return !isAllowedUnderPrefix(upper)
		}
	}
	return false
}

// DangerousPrefixes returns a copy of the refused name prefixes.
func DangerousPrefixes() []string {
	return append([]string(nil), dangerousPrefixes...)
}

// DangerousVarNames returns the exact names refused in addition to
// DangerousPrefixes.
func DangerousVarNames() []string {
	names := make([]string, 0, len(dangerousVars))
	for name := range dangerousVars {
		names = append(names, name)
	}
	return names
}
