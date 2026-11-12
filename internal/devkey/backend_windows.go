//go:build windows

package devkey

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"keygate/internal/fsx"
)

func openNative(home string, _ Options) (Store, error) {
	return &dpapi{path: filepath.Join(home, "device.key.dpapi")}, nil
}

// dpapi protects the blob with CryptProtectData (user scope); the device id is the entropy.
type dpapi struct{ path string }

func (d *dpapi) Name() string { return "dpapi" }

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func (d *dpapi) Save(dev string, secret []byte) error {
	var out windows.DataBlob
	err := windows.CryptProtectData(blob(secret), nil, blob([]byte(dev)), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	enc := unsafe.Slice(out.Data, out.Size)
	return fsx.WriteAtomic(d.path, append([]byte(nil), enc...))
}

func (d *dpapi) Load(dev string) ([]byte, error) {
	enc, err := os.ReadFile(d.path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(enc) == 0 {
		return nil, errors.New("keygate: device key file empty")
	}
	var out windows.DataBlob
	err = windows.CryptUnprotectData(blob(enc), nil, blob([]byte(dev)), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
