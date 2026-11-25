package broker

import (
	"context"
	"strings"
	"testing"

	"keygate/internal/devkey"
)

// A broker started before `kg init` must say to run kg init, not show a raw file-not-found error.
func TestServeWithoutVaultSaysRunInit(t *testing.T) {
	t.Setenv(devkey.EnvBackend, "plain")
	home := t.TempDir()
	b, err := New(Config{Home: home, Keys: func() (devkey.Store, error) { return devkey.NewPlain(home), nil }})
	if err != nil {
		t.Fatal(err)
	}
	err = b.Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "kg init --label") || strings.Contains(err.Error(), "device.json") {
		t.Fatalf("Serve on an empty home = %v, want a hint to run kg init without the device.json detail", err)
	}
}
