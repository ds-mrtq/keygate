package kcrypto

import (
	"bytes"
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
