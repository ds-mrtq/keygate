// Package envname validates environment variable names that KeyGate sets in a child process.
// Loader and interpreter variables are refused: they would let a caller run its own code
// inside an allowed program that receives secrets.
package envname

import (
	"fmt"
	"regexp"
	"strings"
)

var valid = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var denyExact = map[string]bool{
	"PATH": true, "JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true,
	"NODE_OPTIONS": true, "SQLPATH": true, "TNS_ADMIN": true, "CLASSPATH": true, "BASH_ENV": true,
	"PSMODULEPATH": true, "COMSPEC": true, "ENV": true, "IFS": true, "PATHEXT": true,
	"JAVA_HOME": true, "ORACLE_HOME": true, "NODE_PATH": true, "GOFLAGS": true, "GOROOT": true,
	"SYSTEMROOT": true, "WINDIR": true, "HOME": true, "USERPROFILE": true, "TEMP": true, "TMP": true,
	// glibc, interpreters, .NET, shells, plugin loaders: each makes the program load or run caller-chosen code
	"GCONV_PATH": true, "GLIBC_TUNABLES": true, "PERLLIB": true, "TCLLIBPATH": true,
	"PHPRC": true, "PHP_INI_SCAN_DIR": true, "R_PROFILE": true, "R_PROFILE_USER": true,
	"DOTNET_STARTUP_HOOKS": true, "DOTNET_ADDITIONAL_DEPS": true,
	"COR_ENABLE_PROFILING": true, "CORECLR_ENABLE_PROFILING": true,
	"SHELLOPTS": true, "BASHOPTS": true, "PS4": true, "ZDOTDIR": true,
	"OPENSSL_CONF": true, "OPENSSL_ENGINES": true, "GTK_MODULES": true, "GTK_PATH": true,
	"QT_PLUGIN_PATH": true, "GIO_MODULE_DIR": true,
	// tool hooks: git, ssh, less, build tools and TLS clients run a caller-chosen program or trust caller-chosen roots
	"GIT_SSH": true, "GIT_SSH_COMMAND": true, "GIT_EXEC_PATH": true, "GIT_ASKPASS": true,
	"GIT_CONFIG_COUNT": true, "GIT_CONFIG_GLOBAL": true, "GIT_EXTERNAL_DIFF": true, "SSH_ASKPASS": true,
	"LESSOPEN": true, "LESSCLOSE": true, "PAGER": true, "EDITOR": true,
	"RUSTC_WRAPPER": true, "CC": true, "MAKEFLAGS": true, "NPM_CONFIG_SCRIPT_SHELL": true,
	"GOTOOLCHAIN": true, "GOENV": true, "SSL_CERT_FILE": true, "CURL_CA_BUNDLE": true, "NODE_EXTRA_CA_CERTS": true,
}

// LUA_ covers versioned LUA_INIT_5_4/LUA_PATH_5_4; *_PROFILER covers the _32/_64 path variants.
var denyPrefix = []string{"LD_", "DYLD_", "PYTHON", "PERL5", "RUBY", "LUA_", "COR_PROFILER", "CORECLR_PROFILER",
	"GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"}

// Check returns an error when name is not a safe variable name.
func Check(name string) error {
	if !valid.MatchString(name) {
		return fmt.Errorf("tên biến môi trường %q không hợp lệ (cần ^[A-Za-z_][A-Za-z0-9_]*$)", name)
	}
	u := strings.ToUpper(name)
	if denyExact[u] {
		return fmt.Errorf("tên biến môi trường %q bị cấm (biến nạp mã/hệ thống)", name)
	}
	for _, p := range denyPrefix {
		if strings.HasPrefix(u, p) {
			return fmt.Errorf("tên biến môi trường %q bị cấm (tiền tố %s)", name, p)
		}
	}
	return nil
}
