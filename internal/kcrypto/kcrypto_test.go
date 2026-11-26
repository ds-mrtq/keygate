package kcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestWrapRoundTrip(t *testing.T) {
	priv, pub := GenerateX25519()
	vk := NewVaultKey()
	w, err := WrapKey("vlt_abcdefghijklmnop", 3, "dev_abcdefghij", pub, vk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapKey("vlt_abcdefghijklmnop", 3, w, priv)
	if err != nil || !bytes.Equal(got, vk) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := UnwrapKey("vlt_abcdefghijklmnop", 4, w, priv); err == nil {
		t.Fatal("wrong epoch must fail (info binds epoch)")
	}
	if _, err := UnwrapKey("vlt_bbbbbbbbbbbbbbbb", 3, w, priv); err == nil {
		t.Fatal("wrong vault must fail")
	}
	other, _ := GenerateX25519()
	if _, err := UnwrapKey("vlt_abcdefghijklmnop", 3, w, other); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestWrapRejectsInvalidInputs(t *testing.T) {
	const vault, epoch, recipient = "vlt_abcdefghijklmnop", 3, "dev_abcdefghij"
	priv, pub := GenerateX25519()
	key := NewVaultKey()
	w, err := WrapKey(vault, epoch, recipient, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	var lowOrder [32]byte
	if _, err := WrapKey(vault, epoch, recipient, lowOrder, key); err == nil {
		t.Fatal("wrap accepted a low-order recipient public key")
	}
	for _, tc := range []struct {
		name string
		edit func(*Wrap)
		want error
	}{
		{"missing recipient", func(w *Wrap) { w.Rcpt = "" }, ErrBadWrap},
		{"noncanonical public key", func(w *Wrap) { w.Eph += "\n" }, ErrBadWrap},
		{"short nonce", func(w *Wrap) { w.Nonce = B64(make([]byte, NonceSize-1)) }, ErrBadWrap},
		{"short ciphertext", func(w *Wrap) { w.CT = B64([]byte("short")) }, ErrBadWrap},
		{"low-order ephemeral key", func(w *Wrap) { w.Eph = B64(lowOrder[:]) }, ErrDecrypt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := w
			tc.edit(&invalid)
			if got, err := UnwrapKey(vault, epoch, invalid, priv); got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("unwrap returned key data or the wrong error: got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAEADRejectsInvalidInputs(t *testing.T) {
	key := NewVaultKey()
	nonce := RandBytes(NonceSize)
	plaintext, aad := []byte("fake secret"), []byte("item metadata")
	ct, err := Seal(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(key, nonce, ct, aad); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("valid ciphertext did not recover plaintext: %v", err)
	}
	badCT := bytes.Clone(ct)
	badCT[len(badCT)-1] ^= 1
	for _, tc := range []struct {
		name                string
		key, nonce, ct, aad []byte
	}{
		{"short key", key[:KeySize-1], nonce, ct, aad},
		{"short nonce", key, nonce[:NonceSize-1], ct, aad},
		{"modified ciphertext", key, nonce, badCT, aad},
		{"changed metadata", key, nonce, ct, []byte("other metadata")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := Open(tc.key, tc.nonce, tc.ct, tc.aad); got != nil || !errors.Is(err, ErrDecrypt) {
				t.Fatalf("open returned plaintext or the wrong error: %v", err)
			}
		})
	}
	if got, err := Seal(key[:KeySize-1], nonce, plaintext, aad); got != nil || err == nil {
		t.Fatal("seal accepted a short key")
	}
	if got, err := Seal(key, nonce[:NonceSize-1], plaintext, aad); got != nil || err == nil {
		t.Fatal("seal accepted a short nonce")
	}
}

func TestKeyDerivationVectors(t *testing.T) {
	t.Run("Argon2id", func(t *testing.T) {
		// Reference libargon2 argon2id_hash_raw, version 0x13.
		const want = "8ab317c987f559ebf64118f53f8c77495ebc2a03e55a1919de95bf625a25cd4f"
		got := Argon2ID([]byte("fake test password"), []byte("test salt only!!"), Argon2Params{T: 3, M: 128, P: 2})
		if hex.EncodeToString(got) != want {
			t.Fatal("Argon2id derivation changed")
		}
	})
	t.Run("item key", func(t *testing.T) {
		// Independently computed with HMAC-SHA256 and the documented HKDF info encoding.
		const want = "e2426b8d7f14bf2e21893de68ed605c4d5c86498f1018c27f5a7985601089492"
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		got := ItemKey(key, "vlt_abcdefghijklmnop", 0x10203, "itm_abcdefghijklmnop")
		if hex.EncodeToString(got) != want {
			t.Fatal("item key derivation changed")
		}
	})
}

func TestMACVector(t *testing.T) {
	// RFC 4231, test case 1 (HMAC-SHA-256).
	const want = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	if got := MAC(bytes.Repeat([]byte{0x0b}, 20), []byte("Hi There")); hex.EncodeToString(got) != want {
		t.Fatal("HMAC-SHA256 output changed")
	}
}

func TestIDsAndB64(t *testing.T) {
	if !ValidDeviceID(NewDeviceID()) || !ValidItemID(NewItemID()) || !ValidVaultID(NewVaultID()) {
		t.Fatal("generated ids must validate")
	}
	if ValidDeviceID("dev_ABCDEFGHIJ") || ValidDeviceID("dev_abc") || ValidItemID("dev_abcdefghij") {
		t.Fatal("bad ids accepted")
	}
	if _, err := UnB64("AAB="); err == nil { // non-canonical trailing bits
		t.Fatal("non-canonical base64 accepted")
	}
	if !IsHashRef(SHA256Ref([]byte("x"))) || IsHashRef("sha256:AA") {
		t.Fatal("hash ref check")
	}
}

func TestArgonParamsBounds(t *testing.T) {
	if DefaultArgon2.Validate() != nil {
		t.Fatal("default must be valid")
	}
	if (Argon2Params{T: 1, M: 1 << 30, P: 1}).Validate() == nil {
		t.Fatal("huge memory accepted")
	}
}
