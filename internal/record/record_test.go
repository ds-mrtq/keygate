package record

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"keygate/internal/kcrypto"
)

type vecFile struct {
	Inputs struct {
		DeviceEdPub string `json:"device_ed_pub"`
		VaultKey    string `json:"vault_key"`
	} `json:"inputs"`
	Records []struct {
		Line string `json:"line"`
	} `json:"records"`
}

func loadVectors(tb testing.TB) (vecFile, ed25519.PublicKey, []byte) {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors.json"))
	if err != nil {
		tb.Skipf("vectors not available: %v", err)
	}
	var v vecFile
	if err := json.Unmarshal(raw, &v); err != nil {
		tb.Fatal(err)
	}
	pub, _ := hex.DecodeString(v.Inputs.DeviceEdPub)
	vk, _ := hex.DecodeString(v.Inputs.VaultKey)
	return v, pub, vk
}

// FuzzParseRecord: parse + verify + hash + re-marshal must never panic on arbitrary input.
func FuzzParseRecord(f *testing.F) {
	v, pub, _ := loadVectors(f)
	for _, r := range v.Records {
		f.Add([]byte(r.Line))
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"v":1,"vault":"vlt_abcdefghijklmnop","merge":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(data)
		if err != nil {
			return
		}
		_ = r.Verify(pub)
		_, _ = r.Hash()
		_, _ = r.Canonical()
		_ = r.AAD()
		line, err := r.Marshal()
		if err != nil {
			t.Fatalf("marshal parsed record: %v", err)
		}
		if _, err := Parse(line); err != nil {
			t.Fatalf("re-parse of own output failed: %v", err)
		}
	})
}

func TestParseStrict(t *testing.T) {
	v, pub, vk := loadVectors(t)
	line := []byte(v.Records[0].Line)
	r, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(pub); err != nil {
		t.Fatal(err)
	}
	if p, err := r.Decrypt(vk); err != nil || p.Value != "hunter2" {
		t.Fatalf("decrypt: %v", err)
	}
	// wrong epoch key / tampered AAD fields fail
	r2 := *r
	r2.Seq = 9
	if _, err := r2.Decrypt(vk); err == nil {
		t.Fatal("decrypt must fail when AAD fields change")
	}
	for name, mut := range map[string]func(m map[string]any){
		"version": func(m map[string]any) { m["v"] = 2 },
		"vault":   func(m map[string]any) { m["vault"] = "x" },
		"op":      func(m map[string]any) { m["op"] = "del" },
		"seq0":    func(m map[string]any) { m["seq"] = 0 },
		"prev-seq1": func(m map[string]any) {
			m["prev"] = "sha256:" + "00000000000000000000000000000000000000000000000000000000000000aa"
		},
		"epoch0":  func(m map[string]any) { m["epoch"] = 0 },
		"nonce":   func(m map[string]any) { m["nonce"] = "AAAA" },
		"unknown": func(m map[string]any) { m["zzz"] = 1 },
		"sig":     func(m map[string]any) { m["sig"] = "AAAA" },
	} {
		var m map[string]any
		_ = json.Unmarshal(line, &m)
		mut(m)
		b, _ := json.Marshal(m)
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: expected parse error", name)
		}
	}
	if _, err := Parse(append(append([]byte(nil), line...), []byte(` {}`)...)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestTombstoneHasNoValue(t *testing.T) {
	_, _, vk := loadVectors(t)
	r := &Record{V: 1, Vault: "vlt_abcdefghijklmnop", Item: "itm_abcdefghijklmnop", Dev: "dev_abcdefghij", Seq: 1, Epoch: 1, Op: OpTombstone}
	if err := r.Encrypt(vk, Plain{Name: "n", Value: "must-be-dropped"}); err != nil {
		t.Fatal(err)
	}
	p, err := r.Decrypt(vk)
	if err != nil || p.Value != "" || p.Name != "n" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestRecordBindsMetadata(t *testing.T) {
	key := kcrypto.NewVaultKey()
	pub, priv := kcrypto.GenerateSignKey()
	r := Record{V: 1, Vault: kcrypto.NewVaultID(), Item: kcrypto.NewItemID(), Dev: kcrypto.NewDeviceID(), Seq: 7, Epoch: 2, Op: OpPut,
		Parent: StrPtr(kcrypto.SHA256Ref([]byte("fake-parent"))), Prev: StrPtr(kcrypto.SHA256Ref([]byte("fake-previous"))),
		Merge: []string{kcrypto.SHA256Ref([]byte("fake-merge"))}}
	want := Plain{Name: "test/token", Value: "fake-record-value", EnvName: "TEST_TOKEN"}
	if err := r.Encrypt(key, want); err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(pub); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	if got, err := r.Decrypt(key); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("valid record did not recover the original payload: %v", err)
	}
	otherHash := kcrypto.SHA256Ref([]byte("fake-other-record"))
	for _, tc := range []struct {
		name        string
		change      func(*Record)
		bindsCipher bool
	}{
		{"vault", func(r *Record) { r.Vault = kcrypto.NewVaultID() }, true},
		{"item", func(r *Record) { r.Item = kcrypto.NewItemID() }, true},
		{"parent", func(r *Record) { r.Parent = StrPtr(otherHash) }, true},
		{"device", func(r *Record) { r.Dev = kcrypto.NewDeviceID() }, true},
		{"sequence", func(r *Record) { r.Seq++ }, true},
		{"epoch", func(r *Record) { r.Epoch++ }, true},
		{"merge", func(r *Record) { r.Merge = []string{otherHash} }, false},
		{"previous", func(r *Record) { r.Prev = StrPtr(otherHash) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := r
			tc.change(&changed)
			if err := changed.Verify(pub); !errors.Is(err, kcrypto.ErrBadSignature) {
				t.Fatalf("want ErrBadSignature, got %v", err)
			}
			if tc.bindsCipher {
				if got, err := changed.Decrypt(key); !errors.Is(err, kcrypto.ErrDecrypt) || !reflect.DeepEqual(got, Plain{}) {
					t.Fatalf("changed metadata must return ErrDecrypt without a payload, got %v", err)
				}
			}
		})
	}
}

func TestDecryptRejectsInvalidPlaintext(t *testing.T) {
	key := kcrypto.NewVaultKey()
	const put = `{"name":"test/token","value":"fake-record-value"}`
	for _, tc := range []struct {
		name, op, payload string
		valid             bool
	}{
		{"valid put", OpPut, put, true},
		{"unknown field", OpPut, `{"name":"test/token","value":"fake-record-value","unexpected":true}`, false},
		{"value in tombstone", OpTombstone, put, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Record{V: 1, Vault: kcrypto.NewVaultID(), Item: kcrypto.NewItemID(), Dev: kcrypto.NewDeviceID(), Seq: 1, Epoch: 1, Op: tc.op}
			nonce := kcrypto.RandBytes(kcrypto.NonceSize)
			itemKey := kcrypto.ItemKey(key, r.Vault, r.Epoch, r.Item)
			ct, err := kcrypto.Seal(itemKey, nonce, []byte(tc.payload), r.AAD())
			if err != nil {
				t.Fatal(err)
			}
			r.Nonce, r.CT = kcrypto.B64(nonce), kcrypto.B64(ct)
			got, err := r.Decrypt(key)
			if tc.valid {
				if err != nil || got.Name != "test/token" || got.Value != "fake-record-value" {
					t.Fatalf("valid plaintext did not round trip: %v", err)
				}
			} else if !errors.Is(err, kcrypto.ErrDecrypt) || !reflect.DeepEqual(got, Plain{}) {
				t.Fatalf("invalid plaintext must return ErrDecrypt without a payload, got %v", err)
			}
		})
	}
}

// L2: one signed object has exactly one accepted line encoding.
func TestNonCanonicalRejected(t *testing.T) {
	v, _, _ := loadVectors(t)
	line := v.Records[0].Line
	for name, mut := range map[string]string{
		"whitespace":     strings.Replace(line, `{"v":1,`, `{ "v":1,`, 1),
		"case variant":   strings.Replace(line, `"v":1`, `"V":1`, 1),
		"duplicate key":  strings.Replace(line, `{"v":1,`, `{"v":1,"v":1,`, 1),
		"unicode escape": strings.Replace(line, `"op":"put"`, `"op":"\u0070ut"`, 1),
		"crlf in base64": strings.Replace(line, `"nonce":"`, `"nonce":"\r\n`, 1),
	} {
		if mut == line {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := Parse([]byte(mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(line)); err != nil {
		t.Fatal(err)
	}
}
