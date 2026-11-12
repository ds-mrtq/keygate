//go:build darwin

package devkey

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os/exec"
	"strings"

	"keygate/internal/kcrypto"
)

const (
	securityBin = "/usr/bin/security"
	service     = "keygate"
)

func openNative(string, Options) (Store, error) { return &keychain{}, nil }

// keychain uses the macOS login keychain through the security CLI. The secret is hex
// encoded and fed to `security -i` on stdin so it never appears in argv.
type keychain struct{}

func (k *keychain) Name() string { return "keychain" }

func (k *keychain) Save(dev string, secret []byte) error {
	if !kcrypto.ValidDeviceID(dev) {
		return errors.New("keygate: invalid device id")
	}
	cmd := exec.Command(securityBin, "-i")
	cmd.Stdin = strings.NewReader("add-generic-password -U -s " + service + " -a " + dev + " -w " + hex.EncodeToString(secret) + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.New("keygate: keychain save failed: " + strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (k *keychain) Load(dev string) ([]byte, error) {
	cmd := exec.Command(securityBin, "find-generic-password", "-s", service, "-a", dev, "-w")
	out, err := cmd.Output()
	if err != nil {
		return nil, ErrNotFound
	}
	return hex.DecodeString(strings.TrimSpace(string(out)))
}
