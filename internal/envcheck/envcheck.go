package envcheck

import "strings"

var dangerousVars = map[string]bool{
	// Library injection
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"LD_AUDIT":              true,
	"LD_PROFILE_OUTPUT":     true,
	"LD_DEBUG_OUTPUT":       true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
	"DYLD_FRAMEWORK_PATH":   true,
	// dyld consults the FALLBACK paths whenever a dylib/framework is not found
	// at its install name — same injection primitive as DYLD_LIBRARY_PATH.
	"DYLD_FALLBACK_LIBRARY_PATH":   true,
	"DYLD_FALLBACK_FRAMEWORK_PATH": true,

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
	"GIT_ASKPASS":  true,

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
	"PYTHONUSERBASE": true,
	"RUBYLIB":             true,
	"RUBYOPT":             true,
	"BUNDLE_GEMFILE":      true,
	"GEM_HOME":            true,
	"GEM_PATH":            true,
	"BUNDLE_PATH":         true,
	"PERL5LIB":            true,
	"PERL5OPT":            true,
	"CLASSPATH":           true,
	"DOTNET_ROOT":         true,
	"DOTNET_STARTUP_HOOKS": true,
	"LUA_PATH":            true,
	"LUA_CPATH":           true,
	"PHPRC":               true,
	"PHP_INI_SCAN_DIR":    true,

	// Go build injection
	"GOFLAGS":      true,
	"CGO_CFLAGS":   true,
	"CGO_LDFLAGS":  true,
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

	// Package manager redirection
	"PIP_INDEX_URL":       true,
	"PIP_EXTRA_INDEX_URL": true,
	"PIP_CONFIG_FILE":     true,
	"PIP_TARGET":          true,
	"NPM_CONFIG_REGISTRY": true,
	"NPM_CONFIG_PREFIX":   true,
	"NPM_CONFIG_USERCONFIG": true,
	// Same primitive as USERCONFIG one level up: a redirected global npmrc
	// can set registry, scripts-prepend-node-path, and install hooks.
	"NPM_CONFIG_GLOBALCONFIG": true,
	"CARGO_HOME":          true,
	"COMPOSER_HOME":       true,

	// TLS/proxy interception
	"SSL_CERT_FILE":      true,
	"SSL_CERT_DIR":       true,
	"CURL_CA_BUNDLE":     true,
	"REQUESTS_CA_BUNDLE": true,
	"OPENSSL_CONF":       true,
	"HTTP_PROXY":         true,
	"HTTPS_PROXY":        true,

	// XDG config/runtime redirection
	"XDG_CONFIG_HOME": true,
	"XDG_RUNTIME_DIR": true,
	"XDG_DATA_HOME":   true,

	// Temp directory hijacking
	"TMPDIR": true,
	"TMP":    true,
	"TEMP":   true,

	// Git command/config injection
	"GIT_SSH":            true,
	"GIT_PAGER":          true,
	"GIT_SSH_COMMAND":    true,
	"GIT_EXTERNAL_DIFF": true,
	"GIT_EDITOR":        true,
	"GIT_CONFIG_GLOBAL":  true,
	"GIT_CONFIG_SYSTEM":  true,
	"GIT_TEMPLATE_DIR":   true,
	"GIT_PROXY_COMMAND":  true,
	"GIT_EXEC_PATH":      true,
	"GIT_DIR":            true,
	"GIT_WORK_TREE":      true,

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
	// that cargo/rustc invokes in place of (or wrapping) the real compiler.
	"RUSTC_WRAPPER":                       true,
	"RUSTC_WORKSPACE_WRAPPER":             true,
	"CARGO_BUILD_RUSTC_WRAPPER":           true,
	"CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER": true,

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

func IsDangerous(name string) bool {
	return dangerousVars[strings.ToUpper(name)]
}

func DangerousVarNames() []string {
	names := make([]string, 0, len(dangerousVars))
	for name := range dangerousVars {
		names = append(names, name)
	}
	return names
}
