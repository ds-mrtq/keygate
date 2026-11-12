package remote

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"keygate/internal/broker/wire"
	"keygate/internal/kcrypto"
)

// Pending is one approval request awaiting a decision on the phone.
type Pending struct {
	RID     string   `json:"rid"`     // 22 chars base64 raw-URL
	Op      string   `json:"op"`      // grant|unlock|session|set-file|import|compare|delete|policy|resolve-conflict
	Secrets []string `json:"secrets"` // each name already sanitized
	Command string   `json:"command"` // already sanitized
	Detail  string   `json:"detail"`  // at most 32768 bytes, never truncated
	Bind    string   `json:"bind"`    // "sha256:<hex>" of the data to be applied, or ""
	Agent   string   `json:"agent"`
	Peer    string   `json:"peer"`
	Prod    bool     `json:"prod"`
	Created int64    `json:"created"` // unix seconds
	Exp     int64    `json:"exp"`
	Choices []string `json:"choices"` // ordered subset of deny|allow|session
}

// Digest binds a decision to exactly the fields the approver saw:
// "sha256:" + hex(sha256(LabelApprovalReq + lp(rid)+lp(op)+u64(len(secrets))+lp(s_i)…+lp(command)+lp(detail)+lp(bind)+u64(exp))).
func (p Pending) Digest() string {
	e := kcrypto.NewEnc(kcrypto.LabelApprovalReq).LPS(p.RID).LPS(p.Op).U64(uint64(len(p.Secrets)))
	for _, s := range p.Secrets {
		e.LPS(s)
	}
	e.LPS(p.Command).LPS(p.Detail).LPS(p.Bind).U64(uint64(p.Exp))
	sum := sha256.Sum256(e.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ViewSession is the open work session, if any.
type ViewSession struct {
	ID    string `json:"id"`
	Start int64  `json:"start"` // unix seconds
}

// ViewSecret is a secret's public metadata (never a value).
type ViewSecret struct {
	Name     string `json:"name"`
	Env      string `json:"env"`
	Kind     string `json:"kind"`
	Prod     bool   `json:"prod"`
	LastUsed int64  `json:"last_used"` // unix seconds, 0 = never
	Conflict bool   `json:"conflict"`
}

// CmdResult is the outcome of a phone command, kept for the last 10.
type CmdResult struct {
	CID  string `json:"cid"`
	OK   bool   `json:"ok"`
	Msg  string `json:"msg"`
	Time int64  `json:"time"` // unix seconds
}

// ViewAudit is one audit line without argv.
type ViewAudit struct {
	Time     int64  `json:"time"` // unix seconds
	Event    string `json:"event"`
	Secret   string `json:"secret"`
	Agent    string `json:"agent"`
	Approval string `json:"approval"`
	Exit     int    `json:"exit"`
}

// View is what the broker publishes (sealed) for every approver device.
type View struct {
	Kind     string           `json:"kind"` // "view"
	Boot     int64            `json:"boot"` // unix ms at broker start
	Time     int64            `json:"time"` // unix ms
	Label    string           `json:"label"`
	Unlocked bool             `json:"unlocked"`
	Session  *ViewSession     `json:"session"` // null when none
	PolicyOK bool             `json:"policy_ok"`
	Secrets  []ViewSecret     `json:"secrets"`
	Grants   []wire.GrantView `json:"grants"`
	Pending  []Pending        `json:"pending"`
	Results  []CmdResult      `json:"results"`
	Audit    []ViewAudit      `json:"audit"`
}

// Decision is the approver's answer to one Pending.
type Decision struct {
	Kind   string `json:"kind"` // "decision"
	RID    string `json:"rid"`
	Digest string `json:"digest"`
	Choice string `json:"choice"` // deny|allow|session
}

// Command is an approver-signed order to the broker.
type Command struct {
	Kind string          `json:"kind"` // "command"
	CID  string          `json:"cid"`
	Boot int64           `json:"boot"` // copied from the View on screen
	Op   string          `json:"op"`   // lock|session-end|session-start|refresh|grant-revoke|set
	Args json.RawMessage `json:"args"`
}

// Kinds of inbound plaintext.
const (
	KindDecision = "decision"
	KindCommand  = "command"
	KindView     = "view"
)

// Strict decodes one JSON value into v, rejecting unknown fields and trailing data.
func Strict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("remote: trailing data")
	}
	return nil
}
