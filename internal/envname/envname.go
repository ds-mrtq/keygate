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
}

var denyPrefix = []string{"LD_", "DYLD_", "PYTHON", "PERL5", "RUBY"}

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
