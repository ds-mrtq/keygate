package approve

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// DomainApproval is the signature domain label for device approvals.
const DomainApproval = "kg/v1/approval\x00"

// DefaultChallengeTTL is how long a challenge stays valid.
const DefaultChallengeTTL = 5 * time.Minute

var (
	// ErrExpired: the challenge deadline passed.
	ErrExpired = errors.New("challenge đã hết hạn")
	// ErrBadApproval: the pasted signature is malformed or does not verify.
	ErrBadApproval = errors.New("chữ ký duyệt không hợp lệ")
)

// Challenge is what a broker shows and another device signs.
type Challenge struct {
	V       int    `json:"v"`
	Vault   string `json:"vault"`
	Nonce   string `json:"nonce"` // base64 raw URL, 16 random bytes
	Secret  string `json:"secret"`
	Command string `json:"command"`
	Expires int64  `json:"exp"` // unix seconds
}

// NewChallenge makes a challenge with a fresh nonce.
func NewChallenge(vault, secret, command string, ttl time.Duration, now time.Time) (Challenge, error) {
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return Challenge{}, err
	}
	return Challenge{V: 1, Vault: vault, Nonce: base64.RawURLEncoding.EncodeToString(n[:]),
		Secret: secret, Command: command, Expires: now.Add(ttl).Unix()}, nil
}

// Encode renders the challenge as one pasteable token.
func (c Challenge) Encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeChallenge parses Encode output.
func DecodeChallenge(s string) (Challenge, error) {
	var c Challenge
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return c, fmt.Errorf("challenge sai định dạng: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("challenge sai định dạng: %w", err)
	}
	if c.V != 1 || c.Vault == "" || c.Nonce == "" {
		return c, errors.New("challenge sai định dạng")
	}
	return c, nil
}

func lp(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
	return append(buf, s...)
}

// Canonical is the byte string that gets signed.
func (c Challenge) Canonical() []byte {
	b := []byte(DomainApproval)
	b = binary.BigEndian.AppendUint64(b, uint64(c.V))
	b = lp(b, c.Vault)
	b = lp(b, c.Nonce)
	b = lp(b, c.Secret)
	b = lp(b, c.Command)
	return binary.BigEndian.AppendUint64(b, uint64(c.Expires))
}

// Prompt is the human-readable description shown on the approving device.
func (c Challenge) Prompt() string {
	return fmt.Sprintf("KeyGate: cho phép dùng secret %q chạy lệnh: %s", Sanitize(c.Secret, MaxPrompt), Sanitize(c.Command, MaxPrompt))
}

// Sign returns "kga1.<dev>.<sig>" for the challenge.
func Sign(c Challenge, dev string, priv ed25519.PrivateKey) string {
	sig := ed25519.Sign(priv, c.Canonical())
	return "kga1." + dev + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Verify checks a signature string against the member keys. The signer must not be selfDev
// (the machine running the broker). Returns the signer's device ID.
func Verify(c Challenge, sigStr, selfDev string, pubs map[string]ed25519.PublicKey, now time.Time) (string, error) {
	if now.Unix() > c.Expires {
		return "", ErrExpired
	}
	parts := strings.Split(strings.TrimSpace(sigStr), ".")
	if len(parts) != 3 || parts[0] != "kga1" {
		return "", fmt.Errorf("%w: sai định dạng", ErrBadApproval)
	}
	dev := parts[1]
	if dev == selfDev {
		return "", fmt.Errorf("%w: phải duyệt từ thiết bị khác máy chạy broker", ErrBadApproval)
	}
	pub, ok := pubs[dev]
	if !ok {
		return "", fmt.Errorf("%w: thiết bị %s không phải thành viên", ErrBadApproval, dev)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w: sai định dạng chữ ký", ErrBadApproval)
	}
	if !ed25519.Verify(pub, c.Canonical(), sig) {
		return "", fmt.Errorf("%w: chữ ký sai", ErrBadApproval)
	}
	return dev, nil
}

// Device is the broker-side approver: it prints a challenge on its own terminal and reads the
// signature a user pasted there (an agent cannot type into that terminal).
type Device struct {
	Vault string
	Self  string                              // this machine's device ID
	Pubs  func() map[string]ed25519.PublicKey // Ed25519 keys of current members
	// ReadLine reads one line from the broker's own TTY (never from the socket or an agent).
	ReadLine func(ctx context.Context, prompt string) (string, error)
	Out      io.Writer
	TTL      time.Duration
	Now      func() time.Time
	// Signer is set by a successful approval to the device ID that signed it.
	Signer string
}

// Approve uses prompt as the command text with an empty secret name.
func (d *Device) Approve(ctx context.Context, prompt string) error {
	return d.ApproveSecret(ctx, "", prompt)
}

// ApproveSecret issues a challenge for (secret, command) and waits for a valid signature.
func (d *Device) ApproveSecret(ctx context.Context, secret, command string) error {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	ch, err := NewChallenge(d.Vault, secret, command, d.TTL, now())
	if err != nil {
		return err
	}
	fmt.Fprintf(d.Out, "\n[KeyGate] Cần duyệt từ thiết bị khác. Secret: %q, lệnh: %s\n", Sanitize(secret, MaxPrompt), Sanitize(command, MaxPrompt))
	fmt.Fprintf(d.Out, "Trên máy khác chạy:  kg approve %s\n", ch.Encode())
	line, err := d.ReadLine(ctx, "Dán chuỗi chữ ký vào đây: ")
	if err != nil && strings.TrimSpace(line) == "" {
		return fmt.Errorf("không đọc được chữ ký: %w", err)
	}
	dev, err := Verify(ch, line, d.Self, d.Pubs(), now())
	if err == nil {
		d.Signer = dev
	}
	return err
}
