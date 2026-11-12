//go:build !windows && !linux && !darwin

package tty

import (
	"errors"
	"os"
)

func isTerminal(*os.File) bool { return false }

func disableEcho(*os.File) (func(), error) {
	return nil, errors.New("tắt echo không hỗ trợ trên hệ điều hành này")
}
