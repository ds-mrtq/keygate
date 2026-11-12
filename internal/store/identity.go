package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"keygate/internal/devkey"
	"keygate/internal/fsx"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
)

// Identity is this device's key material.
type Identity struct {
	Dev    string
	Label  string
	EdPriv ed25519.PrivateKey
	EdPub  ed25519.PublicKey
	XPriv  [32]byte
	XPub   [32]byte
}

// NewIdentity generates a device identity.
func NewIdentity(label string) *Identity {
	pub, priv := kcrypto.GenerateSignKey()
	xp, xpub := kcrypto.GenerateX25519()
	return &Identity{Dev: kcrypto.NewDeviceID(), Label: label, EdPriv: priv, EdPub: pub, XPriv: xp, XPub: xpub}
}

// DeviceID and Sign make Identity a transport.Signer.
func (i *Identity) DeviceID() string       { return i.Dev }
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.EdPriv, msg) }

// LocalMacKey returns the key for MACing local state: HKDF(device Ed25519 seed, "kg/v1/local-mac\0").
func (i *Identity) LocalMacKey() []byte {
	return kcrypto.HKDF(i.EdPriv.Seed(), []byte(kcrypto.LabelLocalMac), 32)
}

// Secret packs Ed25519 seed || X25519 private key (64 bytes) for devkey.Store.
func (i *Identity) Secret() []byte {
	return append(append([]byte(nil), i.EdPriv.Seed()...), i.XPriv[:]...)
}

// Public returns the registration payload (also the body of an add event).
func (i *Identity) Public() members.AddBody {
	return members.AddBody{Dev: i.Dev, Label: i.Label, EdPub: kcrypto.B64(i.EdPub), XPub: kcrypto.B64(i.XPub[:])}
}

// IdentityFromSecret rebuilds an identity from the blob made by Secret.
func IdentityFromSecret(dev, label string, secret []byte) (*Identity, error) {
	if len(secret) != 64 {
		return nil, errors.New("keygate: bad device key blob")
	}
	priv := ed25519.NewKeyFromSeed(secret[:32])
	id := &Identity{Dev: dev, Label: label, EdPriv: priv, EdPub: priv.Public().(ed25519.PublicKey)}
	copy(id.XPriv[:], secret[32:])
	id.XPub = kcrypto.X25519Public(id.XPriv)
	return id, nil
}

// SaveIdentity writes device.json (public) and stores the private key via ks.
func SaveIdentity(home string, id *Identity, ks devkey.Store) error {
	b, err := json.Marshal(id.Public())
	if err != nil {
		return err
	}
	if err := ks.Save(id.Dev, id.Secret()); err != nil {
		return err
	}
	return fsx.WriteAtomic(filepath.Join(home, "device.json"), b)
}

// LoadIdentity reads device.json and loads the private key from ks.
func LoadIdentity(home string, ks devkey.Store) (*Identity, error) {
	b, err := os.ReadFile(filepath.Join(home, "device.json"))
	if err != nil {
		return nil, err
	}
	var pub members.AddBody
	if err := json.Unmarshal(b, &pub); err != nil {
		return nil, errors.New("keygate: device.json corrupt")
	}
	secret, err := ks.Load(pub.Dev)
	if err != nil {
		return nil, err
	}
	id, err := IdentityFromSecret(pub.Dev, pub.Label, secret)
	if err != nil {
		return nil, err
	}
	if kcrypto.B64(id.EdPub) != pub.EdPub || kcrypto.B64(id.XPub[:]) != pub.XPub {
		return nil, errors.New("keygate: device.json does not match the stored key")
	}
	return id, nil
}

// DefaultHome returns $KG_HOME or ~/.keygate.
func DefaultHome() (string, error) {
	if h := os.Getenv("KG_HOME"); h != "" {
		return h, nil
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(u, ".keygate"), nil
}
