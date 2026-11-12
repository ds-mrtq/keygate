// Package transport defines the untrusted sync channel contract.
// Transports move raw signed lines; they never parse, verify or merge.
// All verification happens in the store on the receiving device.
package transport

import (
	"context"
	"errors"
)

// ErrExists is returned when a log seq or member index already exists on the channel.
var ErrExists = errors.New("transport: already exists")

// Since tells the channel what the caller already holds.
type Since struct {
	Members int               // number of member events already held (next index wanted)
	Logs    map[string]uint64 // device id -> highest seq already held
}

// Snapshot is what a channel returns. Lines are raw JSON without trailing newline.
type Snapshot struct {
	Members     [][]byte            // ordered by n, starting at Since.Members
	Logs        map[string][][]byte // device id -> lines ordered by seq, after Since.Logs[dev]
	Checkpoints map[string][]byte   // device id -> latest checkpoint JSON
}

// Signer signs relay requests with the device Ed25519 key.
type Signer interface {
	DeviceID() string
	Sign(msg []byte) []byte
}

// Transport is one sync channel (dir, git, relay).
type Transport interface {
	Name() string
	Pull(ctx context.Context, since Since) (Snapshot, error)
	PushLog(ctx context.Context, dev string, seq uint64, line []byte) error
	PushMember(ctx context.Context, n int, line []byte) error
	PushCheckpoint(ctx context.Context, dev string, body []byte) error
}
