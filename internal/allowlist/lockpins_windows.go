package allowlist

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// FILE_NAME_NORMALIZED | VOLUME_NAME_DOS (both are 0).
const finalPathFlags = 0

// openLocked opens path with FILE_SHARE_READ only (no WRITE/DELETE sharing): while the handle is
// open nobody can write, truncate, delete, rename the file or rename a parent directory. The
// handle must be a regular file (no reparse point) whose final path equals path.
func openLocked(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*os.File, error) {
		windows.CloseHandle(h)
		return nil, e
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fail(err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fail(errors.New("không phải file thường (symlink/junction/thư mục)"))
	}
	buf := make([]uint16, 1024)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), finalPathFlags)
	if err == nil && int(n) > len(buf) {
		buf = make([]uint16, n+1)
		n, err = windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), finalPathFlags)
	}
	if err != nil {
		return fail(err)
	}
	final := windows.UTF16ToString(buf[:n])
	switch {
	case strings.HasPrefix(final, `\\?\UNC\`):
		final = `\\` + final[len(`\\?\UNC\`):]
	case strings.HasPrefix(final, `\\?\`):
		final = final[len(`\\?\`):]
	}
	if !strings.EqualFold(filepath.Clean(final), filepath.Clean(path)) {
		return fail(errors.New("đường dẫn thực của file khác đường dẫn đã chuẩn hóa: " + final))
	}
	return os.NewFile(uintptr(h), path), nil
}
