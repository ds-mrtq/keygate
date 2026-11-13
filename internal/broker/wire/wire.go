// Package wire defines the newline-delimited JSON protocol between kg clients and the broker
// (DESIGN sec 9). One request line, then zero or more "out" frames, then exactly one
// terminal frame ("ok", "exit" or "err").
package wire

import (
	"encoding/json"
	"time"

	"keygate/internal/api"
)

// Command names.
const (
	CmdStatus          = "status"
	CmdList            = "list"
	CmdGrant           = "grant"
	CmdRun             = "run"
	CmdResolve         = "resolve"
	CmdReveal          = "reveal"
	CmdSet             = "set"
	CmdImport          = "import"
	CmdPolicyApply     = "policy-apply"
	CmdLock            = "lock"
	CmdGrants          = "grants"
	CmdGrantsRevoke    = "grants-revoke"
	CmdConflicts       = "conflicts"
	CmdResolveConflict = "resolve-conflict"
	CmdSync            = "sync"
	CmdDelete          = "delete"
	CmdSessionStart    = "session-start"
	CmdSessionEnd      = "session-end"
	CmdSame            = "same"
	CmdCopy            = "copy"
	CmdFingerprint     = "fingerprint"
)

// Error codes carried in Frame.Code.
const (
	CodeBadRequest = "bad_request"
	CodeLocked     = "locked"
	CodeDenied     = "denied"
	CodeBlocked    = "blocked"
	CodePolicy     = "policy"
	CodeConflict   = "conflict"
	CodeNotFound   = "not_found"
	CodeInternal   = "internal"
	// CodePending: the request waits for a human (phone); approve, then run the command again.
	CodePending = "pending"
)

// Request is one client line.
type Request struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Frame types.
const (
	FrameOut  = "out"  // child output chunk (Stream stdout|stderr, Data base64 via []byte)
	FrameOK   = "ok"   // terminal success, Data holds the result JSON
	FrameExit = "exit" // terminal for run: Exit holds the child's exit code
	FrameErr  = "err"  // terminal failure
	FrameNote = "note" // non-terminal progress note for the user (Msg), e.g. waiting for the phone
)

// Frame is one server line.
type Frame struct {
	T      string          `json:"t"`
	Stream string          `json:"s,omitempty"`
	Chunk  []byte          `json:"d,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	Exit   int             `json:"exit,omitempty"`
	Code   string          `json:"code,omitempty"`
	Msg    string          `json:"msg,omitempty"`
}

// GrantArgs is the argument of CmdGrant.
type GrantArgs struct {
	Secret string   `json:"secret"`
	Argv   []string `json:"argv"`
	Agent  string   `json:"agent,omitempty"`
	Dir    string   `json:"dir,omitempty"` // run directory the grant is for (empty = broker cwd)
}

// GrantsRevokeArgs revokes every stored grant of Secret, or all grants when All is set.
type GrantsRevokeArgs struct {
	Secret string `json:"secret,omitempty"`
	All    bool   `json:"all,omitempty"`
}

// RevealArgs names the secret to show. The value is printed on the BROKER's terminal only.
type RevealArgs struct {
	Name string `json:"name"`
}

// SetArgs carries metadata only: the broker asks for the value (hidden) on its own terminal.
// Request.Value must be empty. FromFile (optional) makes the broker read the value from that file
// itself, after a human approval.
type SetArgs struct {
	Request  api.SetRequest `json:"request"`
	FromFile string         `json:"from_file,omitempty"`
}

// ImportArgs names a file for the broker to read itself (after human approval); no values travel here.
// Exactly one of Dotenv / Gitleaks is set.
type ImportArgs struct {
	Dotenv   string `json:"dotenv,omitempty"`
	Gitleaks string `json:"gitleaks,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	Env      string `json:"env,omitempty"`
	Rewrite  bool   `json:"rewrite,omitempty"`
	Compare  bool   `json:"compare,omitempty"`
}

// ImportResult says which secrets were stored (names only).
type ImportResult struct {
	Count int      `json:"count"`
	Names []string `json:"names"`
}

// ConflictHead is one head of a conflicted item (no values).
type ConflictHead struct {
	Hash string `json:"hash"`
	Dev  string `json:"dev"`
	Seq  uint64 `json:"seq"`
	Op   string `json:"op"`
}

// ConflictInfo lists the competing heads of one item.
type ConflictInfo struct {
	Name  string         `json:"name"`
	Item  string         `json:"item"`
	Heads []ConflictHead `json:"heads"`
}

// ResolveConflictArgs picks the head to keep (record hash or device id).
type ResolveConflictArgs struct {
	Name string `json:"name"`
	Keep string `json:"keep"`
}

// SyncArgs selects the channel; empty Via uses what vault.json configures.
type SyncArgs struct {
	Via       string `json:"via,omitempty"`
	VerifyVia string `json:"verify_via,omitempty"`
}

// SyncResult summarises a sync.
type SyncResult struct {
	Channel     string `json:"channel"`
	Pulled      int    `json:"pulled"`
	Pushed      int    `json:"pushed"`
	Fingerprint string `json:"fingerprint"`
	Verified    string `json:"verified,omitempty"` // channel compared by --verify-via
}

// PolicyResult is the outcome of policy-apply.
type PolicyResult struct {
	Hash   string `json:"hash"`
	Grants int    `json:"grants"`
}

// DeleteArgs lists exact secret names to delete (all-or-nothing).
type DeleteArgs struct {
	Names []string `json:"names"`
}

// DeleteResult lists the names deleted.
type DeleteResult struct {
	Names []string `json:"names"`
}

// FingerprintResult is the 6-word fingerprint of the verified local state.
type FingerprintResult struct {
	Fingerprint string `json:"fingerprint"`
}

// CompareItem is the status of one key of the file: same | diff | missing. No values.
type CompareItem struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// CompareResult is the answer to `import --compare`.
type CompareResult struct {
	Items    []CompareItem `json:"items"`
	Extra    []string      `json:"extra,omitempty"`    // vault names under the prefix that the file lacks
	Unparsed []int         `json:"unparsed,omitempty"` // line numbers that are not KEY=VALUE
}

// StatusFull is api.Status plus the work-session state (api.Status itself is frozen).
type StatusFull struct {
	api.Status
	Session      bool       `json:"session"`
	SessionID    string     `json:"session_id,omitempty"`
	SessionStart *time.Time `json:"session_start,omitempty"`
	Pending      int        `json:"pending"`   // requests published to the phone
	Approvers    int        `json:"approvers"` // paired approver devices
}

// SameArgs compares Names[1:] with Names[0] (values never returned).
type SameArgs struct {
	Names []string `json:"names"`
}

// SameItem is the verdict for one name against the first: "same" or "diff".
type SameItem struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// SameResult lists the verdicts.
type SameResult struct {
	Items []SameItem `json:"items"`
}

// CopyPair is one src -> dst copy.
type CopyPair struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

// CopyArgs copies secrets inside the broker; EnvName (optional) overrides env_name on every dst.
type CopyArgs struct {
	Pairs   []CopyPair `json:"pairs"`
	EnvName string     `json:"env_name,omitempty"`
}

// CopyResult lists the destination names created.
type CopyResult struct {
	Names []string `json:"names"`
}
