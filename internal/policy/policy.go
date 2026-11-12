// Package policy parses policy.yaml (a tiny YAML subset, DESIGN sec 9), matches secret
// names against grant keys, applies the PROD default-deny rule and checks the sha256 pin.
package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"path/filepath"
	"unicode"

	"keygate/internal/allowlist"
	"keygate/internal/envname"
	"keygate/internal/fsx"
)

var (
	// ErrDenied means policy refuses the grant (explicit deny, no grant, or PROD default).
	ErrDenied = errors.New("policy từ chối")
	// ErrPinMismatch means policy.yaml does not match state/policy.pin.
	ErrPinMismatch = errors.New("policy.yaml lệch pin: chạy `kg policy apply` sau khi kiểm tra")
	// ErrNoPin means no pin has been written yet.
	ErrNoPin = errors.New("chưa có policy.pin: chạy `kg policy apply`")
)

// Approval modes.
const (
	ApprovalUserPresence = "user-presence"
	ApprovalDevice       = "device"
	ApprovalNone         = "none"
	ApprovalDeny         = "deny"
)

// DefaultTTL applies when a grant has no ttl: 0 = the grant never expires (until revoked).
const DefaultTTL time.Duration = 0

// Grant is one entry of policy.yaml.
type Grant struct {
	Pattern       string // map key: secret name or glob
	Kind          string
	EnvName       string
	TNSAlias      string
	AllowCommands []string          // raw entries, as written
	Entries       []allowlist.Entry // parsed allow_commands
	Approval      string
	TTL           time.Duration
	MaxRuntime    time.Duration // 0 = DefaultMaxRuntime
	AllowAs       []string      // kinds `--as` may switch to (env|file|wallet); empty = none
}

// OracleCfg is the pinned `oracle:` block: the only source of tools that handle DB passwords.
type OracleCfg struct {
	Java     string
	PkiJar   string
	TNSAdmin string
}

// Policy is a parsed policy.yaml.
type Policy struct {
	Grants []Grant
	Oracle OracleCfg
}

// DefaultMaxRuntime applies when a grant has no max_runtime.
const DefaultMaxRuntime = 30 * time.Minute

var kinds = map[string]bool{"": true, "env": true, "file": true, "oracle-wallet": true, "template": true}

var asKinds = map[string]bool{"env": true, "file": true, "wallet": true}

// Parse reads policy.yaml content. Unknown fields are errors (fail closed).
func Parse(data []byte) (*Policy, error) {
	doc, err := parseDoc(data)
	if err != nil {
		return nil, err
	}
	p := &Policy{}
	for k, v := range doc.oracle {
		if v != "" && !filepath.IsAbs(v) && !strings.HasPrefix(v, "/") {
			return nil, fmt.Errorf("oracle.%s phải là đường dẫn tuyệt đối", k)
		}
		switch k {
		case "java":
			p.Oracle.Java = v
		case "pki_jar":
			p.Oracle.PkiJar = v
		case "tns_admin":
			p.Oracle.TNSAdmin = v
		default:
			return nil, fmt.Errorf("oracle: trường lạ %q", k)
		}
	}
	for _, r := range doc.grants {
		g := Grant{Pattern: r.name, Approval: ApprovalUserPresence, TTL: DefaultTTL}
		for k, v := range r.fields {
			switch k {
			case "kind":
				if !kinds[v] {
					return nil, fmt.Errorf("grant %q: kind %q không hợp lệ", r.name, v)
				}
				g.Kind = v
			case "env_name":
				if err := envname.Check(v); err != nil {
					return nil, fmt.Errorf("grant %q: %w", r.name, err)
				}
				g.EnvName = v
			case "tns_alias":
				g.TNSAlias = v
			case "approval":
				switch v {
				case ApprovalUserPresence, ApprovalDevice, ApprovalNone, ApprovalDeny:
					g.Approval = v
				default:
					return nil, fmt.Errorf("grant %q: approval %q không hợp lệ", r.name, v)
				}
			case "ttl":
				d, err := ParseTTL(v)
				if err != nil {
					return nil, fmt.Errorf("grant %q: ttl: %w", r.name, err)
				}
				g.TTL = d
			case "max_runtime":
				d, err := ParseTTL(v)
				if err != nil {
					return nil, fmt.Errorf("grant %q: max_runtime: %w", r.name, err)
				}
				g.MaxRuntime = d
			case "allow_commands", "allow_as":
				return nil, fmt.Errorf("grant %q: %s phải là danh sách [...]", r.name, k)
			default:
				return nil, fmt.Errorf("grant %q: trường lạ %q", r.name, k)
			}
		}
		for k, l := range r.lists {
			switch k {
			case "allow_commands":
				g.AllowCommands = l
				for _, c := range l {
					e, err := allowlist.ParseEntry(c)
					if err != nil {
						return nil, fmt.Errorf("grant %q: %w", r.name, err)
					}
					g.Entries = append(g.Entries, e)
				}
			case "allow_as":
				for _, v := range l {
					if !asKinds[v] {
						return nil, fmt.Errorf("grant %q: allow_as %q không hợp lệ (env|file|wallet)", r.name, v)
					}
				}
				g.AllowAs = l
			default:
				return nil, fmt.Errorf("grant %q: trường %q không phải danh sách", r.name, k)
			}
		}
		if g.Approval == ApprovalNone {
			for _, e := range g.Entries {
				if !e.HasContentPin() {
					return nil, fmt.Errorf("grant %q: approval: none chỉ hợp lệ khi MỌI allow_commands ghim hash nội dung script/chương trình (sha256:…), mục %q chưa có (kg hash <file> để lấy hash)", r.name, e.Raw)
				}
			}
		}
		p.Grants = append(p.Grants, g)
	}
	return p, nil
}

// ParseTTL accepts Go durations plus a "d" (days) suffix.
func ParseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err != nil || n <= 0 {
			return 0, fmt.Errorf("ttl %q không hợp lệ", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("ttl %q không hợp lệ", s)
	}
	return d, nil
}

func isGlob(s string) bool { return strings.ContainsAny(s, "*?") }

// IsProd reports the PROD default-deny condition: env is prod/prd/production, or any token of the
// name (split on non-alphanumerics) is "prod" or "prd" (ebs/prod/x, prod/x, ebs-prod/x, ebs/prd/x).
func IsProd(name, env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "prod", "prd", "production":
		return true
	}
	for _, t := range strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if t == "prod" || t == "prd" {
			return true
		}
	}
	return false
}

// Lookup returns the grant that governs secret name (with its env), or ErrDenied.
// Exact key wins over globs; among globs the one with most literal characters wins.
// PROD secrets are denied unless an exact-name grant with approval user-presence exists.
func (p *Policy) Lookup(name, env string) (*Grant, error) {
	var best *Grant
	bestScore := -1
	for i := range p.Grants {
		g := &p.Grants[i]
		var score int
		switch {
		case g.Pattern == name:
			score = 1 << 20
		case isGlob(g.Pattern) && allowlist.Glob(g.Pattern, name):
			score = len(strings.NewReplacer("*", "", "?", "").Replace(g.Pattern))
		default:
			continue
		}
		if score > bestScore {
			best, bestScore = g, score
		}
	}
	if IsProd(name, env) {
		if best == nil || best.Pattern != name || best.Approval != ApprovalUserPresence {
			return nil, fmt.Errorf("%w: %q là secret PROD, cần grant đúng tên với approval user-presence", ErrDenied, name)
		}
		return best, nil
	}
	if best == nil {
		return nil, fmt.Errorf("%w: không có grant cho %q", ErrDenied, name)
	}
	if best.Approval == ApprovalDeny {
		return nil, fmt.Errorf("%w: grant %q ghi approval: deny", ErrDenied, best.Pattern)
	}
	return best, nil
}

// Hash returns "sha256:<hex>" of policy bytes.
func Hash(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

type pinFile struct {
	Version uint64 `json:"version"`
	SHA256  string `json:"sha256"`
	MAC     string `json:"mac"`
}

func pinMAC(macKey []byte, version uint64, hash string) string {
	m := hmac.New(sha256.New, macKey)
	m.Write([]byte("kg/v1/local-mac\x00policy.pin\x00"))
	fmt.Fprintf(m, "%d\x00", version)
	m.Write([]byte(hash))
	return hex.EncodeToString(m.Sum(nil))
}

// WritePin records the hash of data as the approved policy with the given (monotonic) version.
func WritePin(pinPath string, data, macKey []byte, version uint64) error {
	h := Hash(data)
	b, _ := json.Marshal(pinFile{Version: version, SHA256: h, MAC: pinMAC(macKey, version, h)})
	return fsx.WriteAtomic(pinPath, b)
}

// ReadPin returns the pinned hash and version after checking the MAC (no policy bytes needed).
func ReadPin(pinPath string, macKey []byte) (hash string, version uint64, err error) {
	raw, err := os.ReadFile(pinPath)
	if os.IsNotExist(err) {
		return "", 0, ErrNoPin
	}
	if err != nil {
		return "", 0, err
	}
	var pf pinFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return "", 0, fmt.Errorf("policy.pin hỏng: %w", err)
	}
	if !hmac.Equal([]byte(pinMAC(macKey, pf.Version, pf.SHA256)), []byte(pf.MAC)) {
		return "", 0, fmt.Errorf("policy.pin sai MAC")
	}
	return pf.SHA256, pf.Version, nil
}

// VerifyPin checks data against the pin file and its MAC and returns the pinned version.
func VerifyPin(pinPath string, data, macKey []byte) (uint64, error) {
	h, v, err := ReadPin(pinPath, macKey)
	if err != nil {
		return 0, err
	}
	if h != Hash(data) {
		return 0, ErrPinMismatch
	}
	return v, nil
}

// Loaded is a policy that passed the pin check.
type Loaded struct {
	Policy  *Policy
	Hash    string
	Version uint64
	Data    []byte
}

// LoadVerified reads policyPath, checks it against the pin and parses it.
func LoadVerified(policyPath, pinPath string, macKey []byte) (*Loaded, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, err
	}
	v, err := VerifyPin(pinPath, data, macKey)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return &Loaded{Policy: p, Hash: Hash(data), Version: v, Data: data}, nil
}

// Names returns grant patterns sorted (for display).
func (p *Policy) Names() []string {
	out := make([]string, 0, len(p.Grants))
	for _, g := range p.Grants {
		out = append(out, g.Pattern)
	}
	sort.Strings(out)
	return out
}
