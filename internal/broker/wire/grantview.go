package wire

import "time"

// GrantView is one stored grant as listed by CmdGrants and published in the phone view.
// Expires is nil when the grant never expires.
type GrantView struct {
	Secret   string     `json:"secret"`
	Pattern  string     `json:"pattern"`
	Path     string     `json:"path"`
	Dir      string     `json:"dir,omitempty"` // canonical run directory the grant is bound to
	Approval string     `json:"approval"`
	By       string     `json:"by"`
	At       time.Time  `json:"at"`
	Expires  *time.Time `json:"expires"`
	Durable  bool       `json:"durable"`
}
