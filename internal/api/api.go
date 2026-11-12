// Package api is the contract between the broker and its clients (CLI, MCP server).
// Nothing in this package ever carries a secret value, except SetRequest.Value which
// travels only from the user's own terminal to the broker over the local socket.
package api

import (
	"context"
	"io"
	"time"
)

// SecretInfo is what an agent may see about a secret.
type SecretInfo struct {
	Name     string     `json:"name"`
	Env      string     `json:"env"`
	Kind     string     `json:"kind"`
	Desc     string     `json:"desc,omitempty"`
	Tags     []string   `json:"tags,omitempty"`
	LastUsed *time.Time `json:"last_used,omitempty"`
	Conflict bool       `json:"conflict"`
}

// GrantInfo describes an active grant (no value).
type GrantInfo struct {
	Secret   string    `json:"secret"`
	Pattern  string    `json:"pattern"`  // allow_commands entry that matched
	Approval string    `json:"approval"` // user-presence|device|none
	Expires  time.Time `json:"expires"`
}

// RunRequest asks the broker to run argv with the given secrets injected.
type RunRequest struct {
	Secrets []string `json:"secrets"`
	Argv    []string `json:"argv"`
	As      string   `json:"as,omitempty"`      // env|file|wallet; empty = secret kind
	Resolve string   `json:"resolve,omitempty"` // path of a ${secret:NAME} template, for kg resolve
	Into    string   `json:"into,omitempty"`    // env var receiving the resolved file path (default KG_RESOLVED)
	Dir     string   `json:"dir,omitempty"`     // working directory of the child
	Agent   string   `json:"agent,omitempty"`   // caller label for audit (e.g. "omp", "claude-code", "mcp")
}

// SetRequest stores or updates a secret. Sent only by `kg set` from the user's terminal.
type SetRequest struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Kind     string   `json:"kind"`
	Env      string   `json:"env"`
	Desc     string   `json:"desc,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	EnvName  string   `json:"env_name,omitempty"`
	TNSAlias string   `json:"tns_alias,omitempty"`
	User     string   `json:"user,omitempty"`
	FileExt  string   `json:"file_ext,omitempty"`
}

// Status of the broker.
type Status struct {
	Unlocked   bool        `json:"unlocked"`
	Device     string      `json:"device"`
	Vault      string      `json:"vault"`
	Epoch      uint64      `json:"epoch"`
	PolicyOK   bool        `json:"policy_ok"`
	Grants     []GrantInfo `json:"grants"`
	LockAfter  string      `json:"lock_after"`
	Conflicts  int         `json:"conflicts"`
	LastSyncAt *time.Time  `json:"last_sync_at,omitempty"`
}

// Broker is implemented by the socket client; MCP and CLI depend only on this.
type Broker interface {
	Status(ctx context.Context) (Status, error)
	List(ctx context.Context) ([]SecretInfo, error)
	RequestGrant(ctx context.Context, secret string, argv []string, agent string) (GrantInfo, error)
	// Run streams the child's redacted stdout/stderr and returns its exit code.
	Run(ctx context.Context, req RunRequest, stdout, stderr io.Writer) (int, error)
}
