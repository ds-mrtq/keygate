package store

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"keygate/internal/fsx"
	"keygate/internal/kcrypto"
	"keygate/internal/members"
)

var requestEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// RequestCode is the registration code a new device hands to the owner (`kg device request`, PWA).
func RequestCode(b members.AddBody) string {
	j, _ := json.Marshal(b)
	return requestEnc.EncodeToString(j)
}

func normalizeCode(code string) string {
	return strings.ToUpper(strings.Join(strings.Fields(code), ""))
}

// RequestWords are the 6 confirmation words of a registration code (shown on both devices).
func RequestWords(code string) string {
	sum := sha256.Sum256([]byte(normalizeCode(code)))
	return Words(sum[:])
}

const labelPairWords = "kg/v1/pair-words\x00"

// PairWords are the 6 confirmation words of a phone pairing: the registration code bound to the
// nonce the laptop put in the pairing link (the nonce never reaches the relay, so a relay cannot
// search for a replacement code whose plain RequestWords collide).
func PairWords(code, nonce string) string {
	sum := sha256.Sum256(kcrypto.NewEnc(labelPairWords).LPS(nonce).LPS(normalizeCode(code)).Bytes())
	return Words(sum[:])
}

// DecodeRequest parses and validates a registration code.
func DecodeRequest(code string) (members.AddBody, error) {
	var b members.AddBody
	raw, err := requestEnc.DecodeString(normalizeCode(code))
	if err != nil {
		return b, errors.New("mã đăng ký sai định dạng")
	}
	if err := json.Unmarshal(raw, &b); err != nil || !kcrypto.ValidDeviceID(b.Dev) || b.Label == "" || len(b.Label) > members.MaxLabel {
		return b, errors.New("mã đăng ký sai định dạng")
	}
	if b.Role != "" && b.Role != members.RoleApprover {
		return b, errors.New("mã đăng ký sai định dạng")
	}
	return b, nil
}

// RoleText is the display name of a device role.
func RoleText(role string) string {
	if role == members.RoleApprover {
		return "duyệt"
	}
	return "đầy đủ"
}

// ReadMembers replays KG_HOME/members.kgl without keys or the vault lock. The file is public and
// unverified here: use it for display and the pairing link, never for a trust decision.
func ReadMembers(home string) (*members.State, error) {
	lines, err := fsx.ReadLines(membersPath(home))
	if err != nil || len(lines) == 0 {
		return nil, errors.New("không đọc được members.kgl")
	}
	return members.Replay(lines)
}

// Devices returns every device of ms (revoked ones included) sorted by id.
func Devices(ms *members.State) []*members.Device {
	out := make([]*members.Device, 0, len(ms.Devices))
	for _, d := range ms.Devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
