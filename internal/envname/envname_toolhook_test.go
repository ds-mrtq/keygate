package envname

import "testing"

// Tool hooks: each name makes git, ssh, less, a build tool or a TLS client run a
// caller-chosen program or trust caller-chosen roots.
func TestCheckToolHookVariables(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "GIT_SSH", wantErr: true},
		{name: "GIT_SSH_COMMAND", wantErr: true},
		{name: "GIT_EXEC_PATH", wantErr: true},
		{name: "GIT_ASKPASS", wantErr: true},
		{name: "GIT_CONFIG_COUNT", wantErr: true},
		{name: "GIT_CONFIG_KEY_0", wantErr: true},
		{name: "GIT_CONFIG_KEY_12", wantErr: true},
		{name: "GIT_CONFIG_VALUE_0", wantErr: true},
		{name: "GIT_CONFIG_VALUE_12", wantErr: true},
		{name: "GIT_CONFIG_GLOBAL", wantErr: true},
		{name: "GIT_EXTERNAL_DIFF", wantErr: true},
		{name: "SSH_ASKPASS", wantErr: true},
		{name: "LESSOPEN", wantErr: true},
		{name: "LESSCLOSE", wantErr: true},
		{name: "PAGER", wantErr: true},
		{name: "EDITOR", wantErr: true},
		{name: "RUSTC_WRAPPER", wantErr: true},
		{name: "CC", wantErr: true},
		{name: "MAKEFLAGS", wantErr: true},
		{name: "NPM_CONFIG_SCRIPT_SHELL", wantErr: true},
		{name: "GOTOOLCHAIN", wantErr: true},
		{name: "GOENV", wantErr: true},
		{name: "SSL_CERT_FILE", wantErr: true},
		{name: "CURL_CA_BUNDLE", wantErr: true},
		{name: "NODE_EXTRA_CA_CERTS", wantErr: true},
		{name: "git_ssh_command", wantErr: true},
		{name: "Git_Config_Key_0", wantErr: true},
		{name: "npm_config_script_shell", wantErr: true},
		{name: "HTTPS_PROXY"},
		{name: "https_proxy"},
		{name: "GIT_TOKEN"},
		{name: "SSH_KEY_PASSPHRASE"},
		{name: "CC_API_KEY"},
		{name: "NPM_TOKEN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Check(tt.name); (err != nil) != tt.wantErr {
				t.Errorf("Check(%q) = %v; want error: %t", tt.name, err, tt.wantErr)
			}
		})
	}
}
