package relay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"keygate/internal/store"
)

func TestGetPairRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v/vlt_test/pair/ABCDEFGHABCDEFGH" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", "67108865") // maxResp + 1
		chunk := strings.Repeat("x", 1<<20)
		for i := 0; i < 64; i++ {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
		_, _ = io.WriteString(w, "x")
	}))
	defer srv.Close()
	c := New(srv.URL, "vlt_test", store.NewIdentity("test"), srv.Client())
	data, _, ready, err := c.GetPair(context.Background(), "ABCDEFGHABCDEFGH")
	if err == nil {
		t.Fatalf("oversized response accepted: ready=%v, body length=%d; want error", ready, len(data))
	}
	if ready || len(data) != 0 {
		t.Fatalf("oversized response returned usable data: ready=%v, body length=%d", ready, len(data))
	}
}
