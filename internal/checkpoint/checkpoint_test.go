package checkpoint

import (
	"errors"
	"testing"

	"keygate/internal/kcrypto"
)

func TestSignVerifyParse(t *testing.T) {
	pub, priv := kcrypto.GenerateSignKey()
	c := &Checkpoint{V: 1, Vault: kcrypto.NewVaultID(), Dev: kcrypto.NewDeviceID(), Time: "2026-11-10T00:00:00Z", MembersN: 3,
		Seen: map[string]uint64{kcrypto.NewDeviceID(): 4, kcrypto.NewDeviceID(): 9}}
	c.Sign(priv)
	b, _ := c.Marshal()
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(pub); err != nil {
		t.Fatal(err)
	}
	p.MembersN++
	if err := p.Verify(pub); !errors.Is(err, kcrypto.ErrBadSignature) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := Parse([]byte(`{"v":1}`)); err == nil {
		t.Fatal("incomplete checkpoint parsed")
	}
}
