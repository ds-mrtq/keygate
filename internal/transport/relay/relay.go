// Package relay implements transport.Transport against the KeyGate relay
// (Cloudflare Worker, DESIGN.md section 8). Every request is signed with the
// device Ed25519 key through transport.Signer.
package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"keygate/internal/transport"
)

const maxResp = 64 << 20

// Client is a relay channel for one vault.
type Client struct {
	base   string
	vault  string
	signer transport.Signer
	http   *http.Client
	now    func() time.Time

	mu   sync.Mutex // serialises requests so KG-Time is strictly increasing
	last time.Time
}

var _ transport.Transport = (*Client)(nil)

// New returns a relay client. baseURL is e.g. https://kg.example.workers.dev
// (no trailing slash needed). hc may be nil.
func New(baseURL, vault string, signer transport.Signer, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		base:   strings.TrimRight(baseURL, "/"),
		vault:  vault,
		signer: signer,
		http:   hc,
		now:    time.Now,
	}
}

// Name implements transport.Transport.
func (c *Client) Name() string { return "relay" }

func lp(b *bytes.Buffer, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	b.Write(n[:])
	b.WriteString(s)
}

// Canonical returns the bytes signed for a relay request:
// "kg/v1/relay-req\x00" + lp(method) + lp(path_with_query) + lp(time) + lp(sha256_hex(body)).
func Canonical(method, pathQuery, timestamp string, body []byte) []byte {
	sum := sha256.Sum256(body)
	var b bytes.Buffer
	b.WriteString("kg/v1/relay-req\x00")
	lp(&b, method)
	lp(&b, pathQuery)
	lp(&b, timestamp)
	lp(&b, hex.EncodeToString(sum[:]))
	return b.Bytes()
}

func (c *Client) do(ctx context.Context, method, pathQuery string, body []byte) ([]byte, int, error) {
	data, code, _, err := c.doR(ctx, method, pathQuery, body, nil)
	return data, code, err
}

// doH sends one signed request with optional extra headers. A 401 means the
// relay did not process the request (stale/out-of-order KG-Time), so it is
// re-signed with a fresh time and sent once more.
func (c *Client) doH(ctx context.Context, method, pathQuery string, body []byte, hdr map[string]string) ([]byte, int, error) {
	data, code, _, err := c.doR(ctx, method, pathQuery, body, hdr)
	return data, code, err
}

// doR is doH that also returns the response headers.
func (c *Client) doR(ctx context.Context, method, pathQuery string, body []byte, hdr map[string]string) ([]byte, int, http.Header, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, code, rh, err := c.send(ctx, method, pathQuery, body, hdr)
	if err == nil && code == http.StatusUnauthorized {
		return c.send(ctx, method, pathQuery, body, hdr)
	}
	return data, code, rh, err
}

func (c *Client) send(ctx context.Context, method, pathQuery string, body []byte, hdr map[string]string) ([]byte, int, http.Header, error) {
	// The relay rejects a KG-Time not strictly greater than the last one it
	// accepted from this device, so keep it strictly increasing (ms resolution).
	t := c.now().UTC().Truncate(time.Millisecond)
	if !t.After(c.last) {
		t = c.last.Add(time.Millisecond)
	}
	c.last = t
	ts := t.Format("2006-01-02T15:04:05.000Z")
	req, err := http.NewRequestWithContext(ctx, method, c.base+pathQuery, bytes.NewReader(body))
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("KG-Device", c.signer.DeviceID())
	req.Header.Set("KG-Time", ts)
	req.Header.Set("KG-Sig", base64.StdEncoding.EncodeToString(c.signer.Sign(Canonical(method, pathQuery, ts, body))))
	if body != nil {
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResp))
	if err != nil {
		return nil, resp.StatusCode, nil, err
	}
	return data, resp.StatusCode, resp.Header, nil
}

func statusErr(op string, code int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return fmt.Errorf("relay: %s: HTTP %d: %s", op, code, msg)
}

func (c *Client) put(ctx context.Context, op, pathQuery string, body []byte) error {
	if body == nil {
		body = []byte{}
	}
	data, code, err := c.do(ctx, http.MethodPut, pathQuery, body)
	if err != nil {
		return err
	}
	switch {
	case code == http.StatusConflict:
		return transport.ErrExists
	case code >= 200 && code < 300:
		return nil
	}
	return statusErr(op, code, data)
}

func (c *Client) get(ctx context.Context, op, pathQuery string, out any) error {
	data, code, err := c.do(ctx, http.MethodGet, pathQuery, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return statusErr(op, code, data)
	}
	return json.Unmarshal(data, out)
}

// Response shapes of the GET routes (lines are the raw stored strings).
type logsResp struct {
	More bool `json:"more"`
	Logs map[string][]struct {
		Seq  uint64 `json:"seq"`
		Line string `json:"line"`
	} `json:"logs"`
}
type membersResp struct {
	Members []struct {
		N    int    `json:"n"`
		Line string `json:"line"`
	} `json:"members"`
}
type checkpointsResp struct {
	Checkpoints map[string]string `json:"checkpoints"`
}

// Pull implements transport.Transport.
func (c *Client) Pull(ctx context.Context, since transport.Since) (transport.Snapshot, error) {
	snap := transport.Snapshot{
		Logs:        map[string][][]byte{},
		Checkpoints: map[string][]byte{},
	}
	pre := "/v/" + c.vault

	var cr checkpointsResp
	if err := c.get(ctx, "get checkpoints", pre+"/checkpoints", &cr); err != nil {
		return snap, err
	}
	for dev, body := range cr.Checkpoints {
		snap.Checkpoints[dev] = []byte(body)
	}
	// Read order matters: checkpoints, then members, then logs, so the snapshot
	// never shows a checkpoint or log newer than the data it references.
	var mr membersResp
	if err := c.get(ctx, "get members", pre+"/members?since="+strconv.Itoa(since.Members), &mr); err != nil {
		return snap, err
	}
	sort.Slice(mr.Members, func(i, j int) bool { return mr.Members[i].N < mr.Members[j].N })
	for _, m := range mr.Members {
		if m.N < since.Members {
			continue
		}
		snap.Members = append(snap.Members, []byte(m.Line))
	}

	held := map[string]uint64{}
	for dev, seq := range since.Logs {
		held[dev] = seq
	}
	for {
		q := pre + "/log"
		var parts []string
		for dev, seq := range held {
			if seq > 0 {
				parts = append(parts, dev+":"+strconv.FormatUint(seq, 10))
			}
		}
		sort.Strings(parts)
		if len(parts) > 0 {
			q += "?since=" + strings.Join(parts, ",")
		}
		var lr logsResp
		if err := c.get(ctx, "get log", q, &lr); err != nil {
			return snap, err
		}
		got := 0
		for dev, rows := range lr.Logs {
			sort.Slice(rows, func(i, j int) bool { return rows[i].Seq < rows[j].Seq })
			for _, r := range rows {
				if r.Seq != held[dev]+1 {
					return snap, fmt.Errorf("relay: log %s: non-contiguous seq %d after %d", dev, r.Seq, held[dev])
				}
				held[dev] = r.Seq
				snap.Logs[dev] = append(snap.Logs[dev], []byte(r.Line))
				got++
			}
		}
		if !lr.More {
			break
		}
		if got == 0 {
			return snap, errors.New("relay: log pagination made no progress")
		}
	}

	return snap, nil
}

// PushLog implements transport.Transport (409 -> transport.ErrExists).
func (c *Client) PushLog(ctx context.Context, dev string, seq uint64, line []byte) error {
	return c.put(ctx, "put log", fmt.Sprintf("/v/%s/log/%s/%d", c.vault, dev, seq), line)
}

// PushMember implements transport.Transport (409 -> transport.ErrExists).
func (c *Client) PushMember(ctx context.Context, n int, line []byte) error {
	return c.put(ctx, "put member", fmt.Sprintf("/v/%s/members/%d", c.vault, n), line)
}

// PushCheckpoint implements transport.Transport.
func (c *Client) PushCheckpoint(ctx context.Context, dev string, body []byte) error {
	return c.put(ctx, "put checkpoint", fmt.Sprintf("/v/%s/checkpoint/%s", c.vault, dev), body)
}

// Msg is one mailbox entry (Body is the sealed envelope line).
type Msg struct {
	ID   string
	From string
	Body []byte
}

// PutView publishes the sealed view for approver `to`; push asks the relay to send a Web Push.
func (c *Client) PutView(ctx context.Context, to string, body []byte, push bool) error {
	var h map[string]string
	if push {
		h = map[string]string{"KG-Push": "1"}
	}
	if body == nil {
		body = []byte{}
	}
	data, code, err := c.doH(ctx, http.MethodPut, fmt.Sprintf("/v/%s/view/%s", c.vault, to), body, h)
	if err != nil {
		return err
	}
	if code >= 200 && code < 300 {
		return nil
	}
	return statusErr("put view", code, data)
}

// GetMsgs returns this signer's mailbox.
func (c *Client) GetMsgs(ctx context.Context) ([]Msg, error) {
	var r struct {
		Msgs []struct {
			ID   string `json:"id"`
			From string `json:"from"`
			Body string `json:"body"`
		} `json:"msgs"`
	}
	if err := c.get(ctx, "get msgs", fmt.Sprintf("/v/%s/msg/%s", c.vault, c.signer.DeviceID()), &r); err != nil {
		return nil, err
	}
	out := make([]Msg, 0, len(r.Msgs))
	for _, m := range r.Msgs {
		out = append(out, Msg{ID: m.ID, From: m.From, Body: []byte(m.Body)})
	}
	return out, nil
}

// DeleteMsg removes one mailbox entry.
func (c *Client) DeleteMsg(ctx context.Context, id string) error {
	data, code, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/v/%s/msg/%s/%s", c.vault, c.signer.DeviceID(), id), nil)
	if err != nil {
		return err
	}
	if code >= 200 && code < 300 {
		return nil
	}
	return statusErr("delete msg", code, data)
}

// Origin is the network origin of a request as the relay saw it (Cloudflare data). It is not
// signed: display only, never a trust decision.
type Origin struct {
	IP      string `json:"ip,omitempty"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Org     string `json:"org,omitempty"`
	UA      string `json:"ua,omitempty"`
}

// GetPair fetches (and consumes) the registration code a phone published under code, with the
// origin of the phone's publish request (zero when the relay did not record one).
func (c *Client) GetPair(ctx context.Context, code string) ([]byte, Origin, error) {
	var o Origin
	data, status, rh, err := c.doR(ctx, http.MethodGet, fmt.Sprintf("/v/%s/pair/%s", c.vault, code), nil, nil)
	if err != nil {
		return nil, o, err
	}
	if status == http.StatusNotFound {
		return nil, o, errors.New("relay: mã ghép không có hoặc đã hết hạn")
	}
	if status != http.StatusOK {
		return nil, o, statusErr("get pair", status, data)
	}
	if h := rh.Get("KG-Pair-Origin"); h != "" {
		if raw, err := base64.StdEncoding.DecodeString(h); err == nil && len(raw) <= 1024 {
			_ = json.Unmarshal(raw, &o)
		}
	}
	return data, o, nil
}

// Seen is the last authenticated request of a device: unix ms and its origin.
type Seen struct {
	Dev  string `json:"dev"`
	Time int64  `json:"t"`
	Origin
}

// Devices lists the last request of every device (key holders only).
func (c *Client) Devices(ctx context.Context) ([]Seen, error) {
	data, status, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v/%s/devices", c.vault), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, statusErr("get devices", status, data)
	}
	var r struct {
		Devices []Seen `json:"devices"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return r.Devices, nil
}
