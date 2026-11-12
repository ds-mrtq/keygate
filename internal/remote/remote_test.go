package remote

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"keygate/internal/kcrypto"
	"keygate/internal/store"
)

type vecFile struct {
	Inputs struct {
		DeviceEdSeed string `json:"device_ed_seed"`
		DeviceXPriv  string `json:"device_x_priv"`
		DeviceEdPub  string `json:"device_ed_pub"`
	} `json:"inputs"`
	Approver struct {
		Dev    string `json:"dev"`
		EdSeed string `json:"ed_seed"`
		XPriv  string `json:"x_priv"`
		EdPub  string `json:"ed_pub"`
		XPub   string `json:"x_pub"`
	} `json:"approver"`
	Msg *struct {
		From      string `json:"from"`
		To        string `json:"to"`
		ID        string `json:"id"`
		Time      string `json:"time"`
		EphPriv   string `json:"eph_priv"`
		Nonce     string `json:"nonce"`
		Plaintext string `json:"plaintext"`
		Line      string `json:"line"`
		Reply     *struct {
			From      string `json:"from"`
			To        string `json:"to"`
			Plaintext string `json:"plaintext"`
			Line      string `json:"line"`
		} `json:"reply"`
	} `json:"msg"`
	PendingDigest struct {
		Pending Pending `json:"pending"`
		Digest  string  `json:"digest"`
	} `json:"pending_digest"`
}

const vault = "vlt_abcdefghijklmnop"

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T) (v vecFile, laptop, phone *store.Identity) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	laptop, err = store.IdentityFromSecret("dev_abcdefghij", "laptop", append(hx(t, v.Inputs.DeviceEdSeed), hx(t, v.Inputs.DeviceXPriv)...))
	if err != nil {
		t.Fatal(err)
	}
	phone, err = store.IdentityFromSecret(v.Approver.Dev, "iphone", append(hx(t, v.Approver.EdSeed), hx(t, v.Approver.XPriv)...))
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestVectorMsg(t *testing.T) {
	v, laptop, phone := load(t)
	m := v.Msg
	var eph [32]byte
	var nonce [12]byte
	copy(eph[:], hx(t, m.EphPriv))
	copy(nonce[:], hx(t, m.Nonce))
	tm, _ := time.Parse(timeFmt, m.Time)
	line, err := SealWith(vault, phone, m.To, laptop.XPub, []byte(m.Plaintext), tm, eph, nonce, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != m.Line {
		t.Fatalf("sealed line differs from vector:\n got %s\nwant %s", line, m.Line)
	}
	from, _, at, pt, err := Open(vault, laptop.Dev, laptop.XPriv, []byte(m.Line), func(d string) ed25519.PublicKey {
		if d == phone.Dev {
			return phone.EdPub
		}
		return nil
	})
	if err != nil || from != phone.Dev || !at.Equal(tm) || string(pt) != m.Plaintext {
		t.Fatalf("open: %v %s %v %q", err, from, at, pt)
	}
	// reply direction: laptop -> phone, opened with the phone's private key
	r := v.Msg.Reply
	from, _, _, pt, err = Open(vault, phone.Dev, phone.XPriv, []byte(r.Line), func(d string) ed25519.PublicKey {
		if d == laptop.Dev {
			return laptop.EdPub
		}
		return nil
	})
	if err != nil || from != laptop.Dev || string(pt) != r.Plaintext {
		t.Fatalf("open reply: %v", err)
	}
}

func TestSealOpenRoundTripAndRejects(t *testing.T) {
	laptop := store.NewIdentity("laptop")
	phone := store.NewIdentity("iphone")
	other := store.NewIdentity("other")
	known := func(d string) ed25519.PublicKey {
		if d == phone.Dev {
			return phone.EdPub
		}
		return nil
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	line, err := Seal(vault, phone, laptop.Dev, laptop.XPub, []byte("hello"), now)
	if err != nil {
		t.Fatal(err)
	}
	from, _, at, pt, err := Open(vault, laptop.Dev, laptop.XPriv, line, known)
	if err != nil || from != phone.Dev || string(pt) != "hello" || !at.Equal(now) {
		t.Fatalf("roundtrip: %v", err)
	}
	reject := func(name string, line []byte, self string, xpriv [32]byte, ed func(string) ed25519.PublicKey) {
		t.Helper()
		if _, _, _, _, err := Open(vault, self, xpriv, line, ed); !errors.Is(err, ErrBadEnvelope) {
			t.Fatalf("%s: want ErrBadEnvelope, got %v", name, err)
		}
	}
	reject("wrong recipient", line, other.Dev, other.XPriv, known)
	reject("unknown sender", line, laptop.Dev, laptop.XPriv, func(string) ed25519.PublicKey { return nil })
	reject("nil lookup", line, laptop.Dev, laptop.XPriv, nil)
	// wrong vault is a signature failure
	if _, _, _, _, err := Open("vlt_zzzzzzzzzzzzzzzz", laptop.Dev, laptop.XPriv, line, known); !errors.Is(err, ErrBadEnvelope) {
		t.Fatalf("wrong vault: %v", err)
	}
	// tamper helpers
	mod := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(line, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	reject("unknown field", mod(func(m map[string]any) { m["x"] = 1 }), laptop.Dev, laptop.XPriv, known)
	reject("v != 1", mod(func(m map[string]any) { m["v"] = 2 }), laptop.Dev, laptop.XPriv, known)
	reject("bad signature (time changed)", mod(func(m map[string]any) { m["time"] = "2020-01-01T00:00:00.000Z" }), laptop.Dev, laptop.XPriv, known)
	reject("bad signature (forged by other)", func() []byte {
		l, _ := Seal(vault, other, laptop.Dev, laptop.XPub, []byte("x"), now)
		return mod2(l, "from", phone.Dev)
	}(), laptop.Dev, laptop.XPriv, known)
	reject("trailing data", append(append([]byte(nil), line...), []byte(` {}`)...), laptop.Dev, laptop.XPriv, known)
	reject("not json", []byte("nope"), laptop.Dev, laptop.XPriv, known)
	// wrong key of the receiver decrypts nothing (but passes to/sig checks only if keys match)
	if strings.Contains(string(line), "hello") {
		t.Fatal("plaintext visible in envelope")
	}
}

func mod2(line []byte, k, val string) []byte {
	var m map[string]any
	_ = json.Unmarshal(line, &m)
	m[k] = val
	b, _ := json.Marshal(m)
	return b
}

func lp(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

func TestVectorPendingDigest(t *testing.T) {
	v, _, _ := load(t)
	p := v.PendingDigest.Pending
	if p.Digest() != v.PendingDigest.Digest {
		t.Fatalf("digest %s != vector %s", p.Digest(), v.PendingDigest.Digest)
	}
	// independent hand-built formula
	b := []byte("kg/v1/approval-req\x00")
	b = append(b, lp([]byte(p.RID))...)
	b = append(b, lp([]byte(p.Op))...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(p.Secrets)))
	for _, s := range p.Secrets {
		b = append(b, lp([]byte(s))...)
	}
	b = append(b, lp([]byte(p.Command))...)
	b = append(b, lp([]byte(p.Detail))...)
	b = append(b, lp([]byte(p.Bind))...)
	b = binary.BigEndian.AppendUint64(b, uint64(p.Exp))
	sum := sha256.Sum256(b)
	if "sha256:"+hex.EncodeToString(sum[:]) != v.PendingDigest.Digest {
		t.Fatal("hand-built digest differs")
	}
	// every displayed field changes the digest
	for name, f := range map[string]func(*Pending){
		"rid": func(p *Pending) { p.RID = "x" }, "op": func(p *Pending) { p.Op = "grant" },
		"secrets": func(p *Pending) { p.Secrets = p.Secrets[:1] }, "command": func(p *Pending) { p.Command += "!" },
		"detail": func(p *Pending) { p.Detail += "!" }, "bind": func(p *Pending) { p.Bind = "" }, "exp": func(p *Pending) { p.Exp++ },
	} {
		q := p
		q.Secrets = append([]string(nil), p.Secrets...)
		f(&q)
		if q.Digest() == p.Digest() {
			t.Fatalf("digest ignores %s", name)
		}
	}
}

func TestMsgKeyLabelsDistinct(t *testing.T) {
	if kcrypto.LabelMsg == kcrypto.LabelMsgKey || kcrypto.LabelMsg == kcrypto.LabelApprovalReq {
		t.Fatal("labels must differ")
	}
}
