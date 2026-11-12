package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
	"io"

	"keygate/internal/checkpoint"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
	"keygate/internal/record"
	"keygate/internal/remote"
	"keygate/internal/store"
)

var update = flag.Bool("update", false, "regenerate testdata/vectors.json")

var vectorsPath = filepath.Join("..", "..", "testdata", "vectors.json")

const (
	vault = "vlt_abcdefghijklmnop"
	dev   = "dev_abcdefghij"
	item  = "itm_abcdefghijklmnop"
)

func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

type Vectors struct {
	Inputs struct {
		DeviceEdSeed  string `json:"device_ed_seed"`
		DeviceXPriv   string `json:"device_x_priv"`
		OwnerEdSeed   string `json:"owner_ed_seed"`
		RecoveryXPriv string `json:"recovery_x_priv"`
		VaultKey      string `json:"vault_key"`
		Nonce         string `json:"nonce"`
		EphPriv       string `json:"eph_priv"`
		DeviceEdPub   string `json:"device_ed_pub"`
		OwnerEdPub    string `json:"owner_ed_pub"`
	} `json:"inputs"`
	ItemKey string   `json:"item_key_hex"`
	Records []RecVec `json:"records"`
	Members []MemVec `json:"members"`
	Wrap    struct {
		EphPub string       `json:"eph_pub_b64"`
		Wrap   kcrypto.Wrap `json:"wrap"`
	} `json:"wrap"`
	Checkpoint struct {
		CanonicalHex string `json:"canonical_hex"`
		Sig          string `json:"sig"`
		Line         string `json:"line"`
	} `json:"checkpoint"`
	Approver ApproverVec `json:"approver"`
	// RevokeApprover is members[4] (not in Members): the laptop revokes the phone with its own key.
	RevokeApprover MemVec  `json:"revoke_approver"`
	Msg            *MsgVec `json:"msg"`
	PendingDigest  struct {
		Pending remote.Pending `json:"pending"`
		Digest  string         `json:"digest"`
	} `json:"pending_digest"`
}

// ApproverVec is the registration of the phone added as members[3].
type ApproverVec struct {
	Dev         string `json:"dev"`
	EdSeed      string `json:"ed_seed"`
	XPriv       string `json:"x_priv"`
	EdPub       string `json:"ed_pub"`
	XPub        string `json:"x_pub"`
	AddBodyJSON string `json:"add_body_json"`
	Code        string `json:"code"`        // registration code (base32 std, no padding)
	Words       string `json:"words"`       // 6 confirmation words of Code
	GenesisPin  string `json:"genesis_pin"` // store.GenesisPinOf(vault, members[0].hash)
}

// MsgVec is one sealed envelope with every input needed to reproduce it byte for byte.
type MsgVec struct {
	From      string  `json:"from"`
	To        string  `json:"to"`
	ID        string  `json:"id"`
	Time      string  `json:"time"`
	EphPriv   string  `json:"eph_priv"` // hex
	Nonce     string  `json:"nonce"`    // hex, 12 bytes
	Plaintext string  `json:"plaintext"`
	Line      string  `json:"line"`
	Reply     *MsgVec `json:"reply,omitempty"` // laptop -> phone direction

}

type RecVec struct {
	Name         string `json:"name"`
	CanonicalHex string `json:"canonical_hex"`
	AADHex       string `json:"aad_hex"`
	Hash         string `json:"record_hash"`
	Sig          string `json:"sig"`
	CT           string `json:"ct"`
	Line         string `json:"line"`
}

type MemVec struct {
	Type         string `json:"type"`
	CanonicalHex string `json:"canonical_hex"`
	Sig          string `json:"sig"`
	Hash         string `json:"hash"`
	Line         string `json:"line"`
}

func gen(t *testing.T) *Vectors {
	t.Helper()
	var v Vectors
	devSeed, devX := seq(1, 32), seq(0x21, 32)
	ownSeed, recX := seq(0x41, 32), seq(0x61, 32)
	vk, nonce, ephPriv := seq(0x81, 32), seq(0xa1, 24), seq(0xc1, 32)
	devPriv := ed25519.NewKeyFromSeed(devSeed)
	ownPriv := ed25519.NewKeyFromSeed(ownSeed)
	var dx, rx, ex [32]byte
	copy(dx[:], devX)
	copy(rx[:], recX)
	copy(ex[:], ephPriv)
	var n24 [24]byte
	copy(n24[:], nonce)
	h := hex.EncodeToString
	v.Inputs.DeviceEdSeed, v.Inputs.DeviceXPriv, v.Inputs.OwnerEdSeed = h(devSeed), h(devX), h(ownSeed)
	v.Inputs.RecoveryXPriv, v.Inputs.VaultKey, v.Inputs.Nonce, v.Inputs.EphPriv = h(recX), h(vk), h(nonce), h(ephPriv)
	v.Inputs.DeviceEdPub = h(devPriv.Public().(ed25519.PublicKey))
	v.Inputs.OwnerEdPub = h(ownPriv.Public().(ed25519.PublicKey))
	v.ItemKey = h(kcrypto.ItemKey(vk, vault, 1, item))

	mk := func(name string, r *record.Record, p record.Plain) {
		if err := r.EncryptWithNonce(vk, n24, p); err != nil {
			t.Fatal(err)
		}
		if err := r.Sign(devPriv); err != nil {
			t.Fatal(err)
		}
		c, _ := r.Canonical()
		hash, _ := r.Hash()
		line, _ := r.Marshal()
		v.Records = append(v.Records, RecVec{Name: name, CanonicalHex: h(c), AADHex: h(r.AAD()), Hash: hash, Sig: r.Sig, CT: r.CT, Line: string(line)})
	}
	r1 := &record.Record{V: 1, Vault: vault, Item: item, Dev: dev, Seq: 1, Epoch: 1, Op: record.OpPut}
	mk("put", r1, record.Plain{Name: "db/test/pass", Value: "hunter2", Desc: "vector", Tags: []string{"a"}, Env: "test", Kind: "env", EnvName: "DB_PASS"})
	h1, _ := r1.Hash()
	r2 := &record.Record{V: 1, Vault: vault, Item: item, Parent: record.StrPtr(h1), Dev: dev, Seq: 2, Prev: record.StrPtr(h1), Epoch: 1, Op: record.OpTombstone}
	mk("tombstone", r2, record.Plain{Name: "db/test/pass"})
	h2, _ := r2.Hash()
	r3 := &record.Record{V: 1, Vault: vault, Item: item, Parent: record.StrPtr(h2), Merge: []string{h1}, Dev: dev, Seq: 3, Prev: record.StrPtr(h2), Epoch: 1, Op: record.OpPut}
	mk("merge", r3, record.Plain{Name: "db/test/pass", Value: "merged", Kind: "env"})

	rxPub := kcrypto.X25519Public(rx)
	w, err := kcrypto.WrapKeyWith(ex, n24, vault, 1, members.RecoveryRcpt, rxPub, vk)
	if err != nil {
		t.Fatal(err)
	}
	epub := kcrypto.X25519Public(ex)
	v.Wrap.EphPub, v.Wrap.Wrap = kcrypto.B64(epub[:]), w
	dxPub := kcrypto.X25519Public(dx)
	wd, err := kcrypto.WrapKeyWith(ex, n24, vault, 1, dev, dxPub, vk)
	if err != nil {
		t.Fatal(err)
	}

	var prev *members.Event
	add := func(typ string, body any) {
		e, err := members.New(vault, uint64(len(v.Members)), prev, typ, body, ownPriv)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := e.Canonical()
		hash, _ := e.Hash()
		line, _ := e.Marshal()
		v.Members = append(v.Members, MemVec{Type: typ, CanonicalHex: h(c), Sig: e.Sig, Hash: hash, Line: string(line)})
		prev = e
	}
	add(members.TypeGenesis, members.GenesisBody{OwnerPub: kcrypto.B64(ownPriv.Public().(ed25519.PublicKey)), RecoveryPub: kcrypto.B64(rxPub[:]),
		ArgonSalt: kcrypto.B64(seq(0xe1, 16)), ArgonParams: kcrypto.DefaultArgon2, Created: "2026-11-10T00:00:00Z"})
	add(members.TypeAdd, members.AddBody{Dev: dev, Label: "laptop-vpc", EdPub: kcrypto.B64(devPriv.Public().(ed25519.PublicKey)), XPub: kcrypto.B64(dxPub[:])})
	add(members.TypeEpoch, members.EpochBody{Epoch: 1, Wraps: []kcrypto.Wrap{wd, w}})

	// approver (phone): add event only, no wrap, no epoch
	apSeed, apX := seq(0x01+0x90, 32), seq(0x01+0xb0, 32)
	apPriv := ed25519.NewKeyFromSeed(apSeed)
	var apx [32]byte
	copy(apx[:], apX)
	apxPub := kcrypto.X25519Public(apx)
	const apDev = "dev_approver22"
	apBody := members.AddBody{Dev: apDev, Label: "iphone", EdPub: kcrypto.B64(apPriv.Public().(ed25519.PublicKey)), XPub: kcrypto.B64(apxPub[:]), Role: members.RoleApprover}
	add(members.TypeAdd, apBody)
	apJSON, _ := json.Marshal(apBody)
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(apJSON)
	codeSum := sha256.Sum256([]byte(code))
	v.Approver.Dev, v.Approver.EdSeed, v.Approver.XPriv = apDev, h(apSeed), h(apX)
	v.Approver.EdPub, v.Approver.XPub = h(apPriv.Public().(ed25519.PublicKey)), h(apxPub[:])
	v.Approver.AddBodyJSON, v.Approver.Code, v.Approver.Words = string(apJSON), code, store.Words(codeSum[:])
	v.Approver.GenesisPin = store.GenesisPinOf(vault, v.Members[0].Hash)
	ra, err := members.New(vault, uint64(len(v.Members)), prev, members.TypeRevokeApprover,
		members.RevokeApproverBody{Dev: apDev, By: dev, Reason: "lost"}, devPriv)
	if err != nil {
		t.Fatal(err)
	}
	raC, _ := ra.Canonical()
	raHash, _ := ra.Hash()
	raLine, _ := ra.Marshal()
	v.RevokeApprover = MemVec{Type: members.TypeRevokeApprover, CanonicalHex: h(raC), Sig: ra.Sig, Hash: raHash, Line: string(raLine)}

	// sealed messages: phone -> laptop (command) and laptop -> phone (reply)
	devID, err := store.IdentityFromSecret(dev, "laptop-vpc", append(append([]byte(nil), devSeed...), devX...))
	if err != nil {
		t.Fatal(err)
	}
	apID, err := store.IdentityFromSecret(apDev, "iphone", append(append([]byte(nil), apSeed...), apX...))
	if err != nil {
		t.Fatal(err)
	}
	mkMsg := func(from *store.Identity, to string, toX [32]byte, ephSeed, nonceSeed byte, idSeed byte, pt string) *MsgVec {
		var eph [32]byte
		var n12 [12]byte
		copy(eph[:], seq(ephSeed, 32))
		copy(n12[:], seq(nonceSeed, 12))
		id := base64.RawURLEncoding.EncodeToString(seq(idSeed, 16))
		tm := time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)
		line, err := remote.SealWith(vault, from, to, toX, []byte(pt), tm, eph, n12, id)
		if err != nil {
			t.Fatal(err)
		}
		return &MsgVec{From: from.Dev, To: to, ID: id, Time: tm.Format("2006-01-02T15:04:05.000Z"), EphPriv: h(eph[:]), Nonce: h(n12[:]), Plaintext: pt, Line: string(line)}
	}
	v.Msg = mkMsg(apID, dev, kcrypto.X25519Public(dx), 0xd0, 0x31, 0x11, `{"kind":"command","cid":"AAAAAAAAAAAAAAAAAAAAAA","op":"lock","args":{}}`)
	v.Msg.Reply = mkMsg(devID, apDev, apxPub, 0xf0, 0x51, 0x21, `{"kind":"view","boot":1,"time":2}`)

	pd := remote.Pending{RID: "AAECAwQFBgcICQoLDA0ODw", Op: "policy", Secrets: []string{"mantis/mantis-api-token", "db/test/pass"}, Command: "kg policy apply (policy.yaml v3)",
		Detail: "+ allow: python mantis_api.py\n- allow: old\nCẢNH BÁO: grant mới", Bind: "sha256:" + hex.EncodeToString(seq(0, 32)), Agent: "claude", Peer: "pid 4242 (node.exe)", Prod: true,
		Created: 1762848000, Exp: 1762849800, Choices: []string{"deny", "allow"}}
	v.PendingDigest.Pending, v.PendingDigest.Digest = pd, pd.Digest()

	cp := &checkpoint.Checkpoint{V: 1, Vault: vault, Dev: dev, Time: "2026-11-10T00:00:00Z", MembersN: 3, Seen: map[string]uint64{dev: 3, "dev_zzzzzzzzzz": 7, "dev_bbbbbbbbbb": 1}}
	cp.Sign(devPriv)
	line, _ := cp.Marshal()
	v.Checkpoint.CanonicalHex, v.Checkpoint.Sig, v.Checkpoint.Line = h(cp.Canonical()), cp.Sig, string(line)
	return &v
}

func TestVectors(t *testing.T) {
	v := gen(t)
	want, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if *update {
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("vectors updated")
		return
	}
	got, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors (run with -update to create): %v", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")), want) {
		t.Fatal("regenerated vectors differ from testdata/vectors.json (format changed? run go test ./internal/vectors -update and review the diff)")
	}
}

// lp / u64 re-implemented here from DESIGN.md sec 2, independent of kcrypto.Enc.
func lp(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}
func u64(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

// TestSpecCrossCheck rebuilds canonical strings by hand per DESIGN.md and compares with the file.
func TestSpecCrossCheck(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	devPub, _ := hex.DecodeString(v.Inputs.DeviceEdPub)
	ownPub, _ := hex.DecodeString(v.Inputs.OwnerEdPub)
	vk, _ := hex.DecodeString(v.Inputs.VaultKey)

	// item key
	info := append([]byte("kg/v1/item-key\x00"), lp([]byte(vault))...)
	info = append(info, u64(1)...)
	info = append(info, lp([]byte(item))...)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, vk, nil, info), key); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key) != v.ItemKey {
		t.Fatal("item key mismatch vs hand-built spec formula")
	}

	for _, rv := range v.Records {
		r, err := record.Parse([]byte(rv.Line))
		if err != nil {
			t.Fatalf("%s: parse: %v", rv.Name, err)
		}
		if err := r.Verify(devPub); err != nil {
			t.Fatalf("%s: verify: %v", rv.Name, err)
		}
		c := []byte("kg/v1/record\x00")
		c = append(c, u64(uint64(r.V))...)
		c = append(c, lp([]byte(r.Vault))...)
		c = append(c, lp([]byte(r.Item))...)
		if r.Parent != nil {
			c = append(c, lp([]byte(*r.Parent))...)
		} else {
			c = append(c, lp(nil)...)
		}
		c = append(c, u64(uint64(len(r.Merge)))...)
		for _, m := range r.Merge {
			c = append(c, lp([]byte(m))...)
		}
		c = append(c, lp([]byte(r.Dev))...)
		c = append(c, u64(r.Seq)...)
		if r.Prev != nil {
			c = append(c, lp([]byte(*r.Prev))...)
		} else {
			c = append(c, lp(nil)...)
		}
		c = append(c, u64(r.Epoch)...)
		c = append(c, lp([]byte(r.Op))...)
		nonce, _ := kcrypto.UnB64(r.Nonce)
		ct, _ := kcrypto.UnB64(r.CT)
		c = append(c, lp(nonce)...)
		c = append(c, lp(ct)...)
		if hex.EncodeToString(c) != rv.CanonicalHex {
			t.Fatalf("%s: canonical differs from hand-built spec string", rv.Name)
		}
		sig, _ := kcrypto.UnB64(r.Sig)
		sum := sha256.Sum256(append(append([]byte(nil), c...), sig...))
		if "sha256:"+hex.EncodeToString(sum[:]) != rv.Hash {
			t.Fatalf("%s: hash mismatch", rv.Name)
		}
		aad := []byte("kg/v1/record\x00")
		aad = append(aad, lp([]byte(r.Vault))...)
		aad = append(aad, lp([]byte(r.Item))...)
		if r.Parent != nil {
			aad = append(aad, lp([]byte(*r.Parent))...)
		} else {
			aad = append(aad, lp(nil)...)
		}
		aad = append(aad, u64(r.Epoch)...)
		aad = append(aad, lp([]byte(r.Dev))...)
		aad = append(aad, u64(r.Seq)...)
		if hex.EncodeToString(aad) != rv.AADHex {
			t.Fatalf("%s: AAD mismatch", rv.Name)
		}
		p, err := r.Decrypt(vk)
		if err != nil || p.Name != "db/test/pass" {
			t.Fatalf("%s: decrypt: %+v %v", rv.Name, p, err)
		}
	}

	// member events
	var prevHash string
	for i, mv := range v.Members {
		e, err := members.Parse([]byte(mv.Line))
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Verify(ownPub); err != nil {
			t.Fatalf("member %d: %v", i, err)
		}
		body, _ := kcrypto.UnB64(e.Body)
		c := []byte("kg/v1/member\x00")
		c = append(c, u64(1)...)
		c = append(c, lp([]byte(vault))...)
		c = append(c, u64(uint64(i))...)
		if i == 0 {
			c = append(c, lp(nil)...)
		} else {
			c = append(c, lp([]byte(prevHash))...)
		}
		c = append(c, lp([]byte(e.Type))...)
		c = append(c, lp(body)...)
		if hex.EncodeToString(c) != mv.CanonicalHex {
			t.Fatalf("member %d canonical mismatch", i)
		}
		prevHash = mv.Hash
	}
	if _, err := members.Replay(linesOf(v.Members)); err != nil {
		t.Fatalf("replay vector chain: %v", err)
	}
	ms, err := members.Replay(linesOf(append(append([]MemVec(nil), v.Members...), v.RevokeApprover)))
	if err != nil || !ms.Devices[v.Approver.Dev].Revoked || ms.Epoch != 1 {
		t.Fatalf("replay with revoke-approver: %v", err)
	}

	// checkpoint
	cp, err := checkpoint.Parse([]byte(v.Checkpoint.Line))
	if err != nil || cp.Verify(devPub) != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	c := []byte("kg/v1/checkpoint\x00")
	c = append(c, u64(1)...)
	c = append(c, lp([]byte(vault))...)
	c = append(c, lp([]byte(dev))...)
	c = append(c, lp([]byte("2026-11-10T00:00:00Z"))...)
	c = append(c, u64(3)...)
	for _, d := range []string{"dev_abcdefghij", "dev_bbbbbbbbbb", "dev_zzzzzzzzzz"} { // sorted ascending
		c = append(c, lp([]byte(d))...)
		c = append(c, u64(cp.Seen[d])...)
	}
	// "dev_abcdefghij" < "dev_bbbbbbbbbb" < "dev_zzzzzzzzzz" lexicographically
	if hex.EncodeToString(c) != v.Checkpoint.CanonicalHex {
		t.Fatal("checkpoint canonical mismatch")
	}

	// wrap opens with the recovery key
	rx, _ := hex.DecodeString(v.Inputs.RecoveryXPriv)
	var rp [32]byte
	copy(rp[:], rx)
	got, err := kcrypto.UnwrapKey(vault, 1, v.Wrap.Wrap, rp)
	if err != nil || !bytes.Equal(got, vk) {
		t.Fatalf("unwrap vector: %v", err)
	}
}

func linesOf(ms []MemVec) [][]byte {
	var out [][]byte
	for _, m := range ms {
		out = append(out, []byte(m.Line))
	}
	return out
}
