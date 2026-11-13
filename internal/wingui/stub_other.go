//go:build !windows

package wingui

import (
	"context"
	"errors"

	"keygate/internal/api"
	"keygate/internal/approve"
)

var errUnsupported = errors.New("chỉ hỗ trợ Windows")

// Secret is Windows-only.
func Secret(context.Context, string) (string, error) { return "", errUnsupported }

// ShowSecret is Windows-only.
func ShowSecret(context.Context, string, string) error { return errUnsupported }

// Line is Windows-only.
func Line(context.Context, string) (string, error) { return "", errUnsupported }

// Review is Windows-only.
func Review(context.Context, string, string) error { return errUnsupported }

// ReviewDoc is Windows-only.
func ReviewDoc(context.Context, string, approve.ReviewDoc) error { return errUnsupported }

// LogWindow is Windows-only.
func LogWindow(context.Context, string) error { return errUnsupported }

// AddSecretMeta is Windows-only.
func AddSecretMeta(context.Context) (api.SetRequest, error) {
	return api.SetRequest{}, errUnsupported
}

// MessageBox is Windows-only.
func MessageBox(string, string) {}
