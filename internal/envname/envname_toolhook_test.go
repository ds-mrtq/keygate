package envname

import (
	"strings"
	"testing"
)

// Tool hooks: each name makes git, ssh, less, a build tool or a TLS client run a
// caller-chosen program or trust caller-chosen roots.
var toolHookNames = []string{
	"GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_ASKPASS",
	"GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_KEY_12", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_VALUE_12",
	"GIT_CONFIG_GLOBAL", "GIT_EXTERNAL_DIFF", "SSH_ASKPASS",
	"LESSOPEN", "LESSCLOSE", "PAGER", "EDITOR",
	"RUSTC_WRAPPER", "CC", "MAKEFLAGS", "NPM_CONFIG_SCRIPT_SHELL",
	"GOTOOLCHAIN", "GOENV", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
}

func mixedCase(s string) string {
	b := []byte(strings.ToLower(s))
	for i := 0; i < len(b); i += 2 {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

func TestCheckToolHookVariables(t *testing.T) {
	type tc struct {
		name    string
		wantErr bool
	}
	var tests []tc
	for _, n := range toolHookNames {
		tests = append(tests,
			tc{name: n, wantErr: true},
			tc{name: strings.ToLower(n), wantErr: true},
			tc{name: mixedCase(n), wantErr: true},
			tc{name: " " + n, wantErr: true},
			tc{name: n + " ", wantErr: true},
			tc{name: "\t" + n, wantErr: true},
			tc{name: n + "\t", wantErr: true},
			tc{name: n + "\n", wantErr: true},
		)
		if len(n) > 2 {
			tests = append(tests, tc{name: n[:2] + " " + n[2:], wantErr: true})
		}
	}
	for _, n := range []string{
		"HTTPS_PROXY", "https_proxy", "Https_Proxy",
		"GIT_TOKEN", "SSH_KEY_PASSPHRASE", "CC_API_KEY", "NPM_TOKEN", "MY_PAGER_TOKEN", "EDITOR_KEY",
	} {
		tests = append(tests, tc{name: n})
	}
	for _, n := range []string{" HTTPS_PROXY", "HTTPS_PROXY ", "\tHTTPS_PROXY", "HTTPS PROXY"} {
		tests = append(tests, tc{name: n, wantErr: true})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Check(tt.name); (err != nil) != tt.wantErr {
				t.Errorf("Check(%q) = %v; want error: %t", tt.name, err, tt.wantErr)
			}
		})
	}
}
