// gen-winres writes the Windows icon assets drawn by internal/icon:
//   - cmd/kg/rsrc_windows_amd64.syso: COFF object with RT_ICON + RT_GROUP_ICON (id 1) and RT_VERSION
//     (FileDescription/ProductName "KeyGate"); the Go linker embeds it into kg.exe / kgw.exe, so
//     Explorer, the taskbar, shortcuts and Windows' tray-icon settings show the logo and the name;
//   - docs/brand/keygate.ico and docs/brand/keygate.svg.
//
// Run from the repo root: go run ./tools/gen-winres
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf16"

	"keygate/internal/icon"
)

var sizes = []int{16, 20, 24, 32, 40, 48, 64, 256}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-winres:", err)
		os.Exit(1)
	}
}

func run() error {
	images := icon.IconImages(icon.Brand, sizes...)
	files := map[string][]byte{
		"cmd/kg/rsrc_windows_amd64.syso": syso(images),
		"docs/brand/keygate.ico":         icon.ICO(images),
		"docs/brand/keygate.svg":         []byte(icon.SVG(icon.Brand, icon.Style{})),
	}
	for name, data := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(name, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

const (
	rtIcon      = 3
	rtGroupIcon = 14
	rtVersion   = 16
	langNeutral = 0
	groupID     = 1
)

// versionStrings are the StringFileInfo entries; Windows shows FileDescription as the app name
// (Settings → Taskbar → Other system tray icons, notifications, Task Manager). Version numbers
// stay 0: this object is generated once and committed, the release version is in `kg version`.
var versionStrings = [][2]string{
	{"CompanyName", "KeyGate"},
	{"FileDescription", "KeyGate"},
	{"ProductName", "KeyGate"},
	{"LegalCopyright", "MIT License"},
	// .NET FileVersionInfo ignores a string table without FileVersion.
	{"FileVersion", "0.0.0.0 (see kg version)"},
	{"ProductVersion", "0.0.0.0 (see kg version)"},
}

// versionInfo encodes a VS_VERSIONINFO block: VS_FIXEDFILEINFO (all versions 0, VFT_APP), one
// StringTable 040904B0 (en-US, UTF-16) and the matching VarFileInfo Translation.
func versionInfo() []byte {
	var fixed bytes.Buffer
	binary.Write(&fixed, binary.LittleEndian, [13]uint32{
		0xFEEF04BD, 0x00010000, // signature, struct version
		0, 0, 0, 0, // file and product versions
		0x3F, 0, // flags mask, flags
		0x00040004, 1, 0, // VOS_NT_WINDOWS32, VFT_APP, subtype
		0, 0, // date
	})
	var strs [][]byte
	for _, kv := range versionStrings {
		v := utf16z(kv[1])
		strs = append(strs, verNode(kv[0], 1, v, uint16(len(v)/2), nil))
	}
	table := verNode("040904B0", 1, nil, 0, strs)
	sfi := verNode("StringFileInfo", 1, nil, 0, [][]byte{table})
	tr := []byte{0x09, 0x04, 0xB0, 0x04} // 0x0409, 1200
	vfi := verNode("VarFileInfo", 1, nil, 0, [][]byte{verNode("Translation", 0, tr, uint16(len(tr)), nil)})
	return verNode("VS_VERSION_INFO", 0, fixed.Bytes(), uint16(fixed.Len()), [][]byte{sfi, vfi})
}

// verNode encodes one version-resource node: wLength, wValueLength, wType, key (UTF-16, NUL),
// padding to 4, value, padding to 4, children (each padded to 4). wLength excludes the trailing
// padding of the node.
func verNode(key string, typ uint16, value []byte, valueLen uint16, children [][]byte) []byte {
	var b bytes.Buffer
	pad := func() {
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, valueLen, typ})
	b.Write(utf16z(key))
	pad()
	b.Write(value)
	for i, c := range children {
		if i > 0 || len(value) > 0 {
			pad()
		}
		b.Write(c)
	}
	out := b.Bytes()
	binary.LittleEndian.PutUint16(out, uint16(len(out)))
	return out
}

func utf16z(s string) []byte {
	u := append(utf16.Encode([]rune(s)), 0)
	out := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2*i:], c)
	}
	return out
}

type leaf struct {
	id   uint16
	data []byte
}

// syso builds an AMD64 COFF object with one .rsrc section holding the icon images (ids 1..n), one
// group icon (id groupID) and the version info (id 1). Data-entry RVAs are section offsets fixed up
// by ADDR32NB relocations.
func syso(images []icon.IconImage) []byte {
	var group bytes.Buffer
	binary.Write(&group, binary.LittleEndian, [3]uint16{0, 1, uint16(len(images))})
	icons := make([]leaf, len(images))
	for i, im := range images {
		group.Write(icon.GroupEntry(im))
		binary.Write(&group, binary.LittleEndian, uint32(len(im.Data)))
		binary.Write(&group, binary.LittleEndian, uint16(i+1))
		icons[i] = leaf{uint16(i + 1), im.Data}
	}
	types := []struct {
		id     uint16
		leaves []leaf
	}{{rtIcon, icons}, {rtGroupIcon, []leaf{{groupID, group.Bytes()}}}, {rtVersion, []leaf{{1, versionInfo()}}}} // sorted by type id

	// Layout: root dir, type dirs, name dirs (one language each), data entries, then data.
	const dirSize, entSize, dataEntSize = 16, 8, 16
	nLeaves := 0
	for _, t := range types {
		nLeaves += len(t.leaves)
	}
	typeDirsAt := dirSize + entSize*len(types)
	nameDirsAt := typeDirsAt
	for _, t := range types {
		nameDirsAt += dirSize + entSize*len(t.leaves)
	}
	dataEntsAt := nameDirsAt + nLeaves*(dirSize+entSize)
	dataAt := dataEntsAt + nLeaves*dataEntSize

	var sec bytes.Buffer
	le := func(v any) { binary.Write(&sec, binary.LittleEndian, v) }
	dir := func(nIDs int) { le([3]uint32{}); le([2]uint16{0, uint16(nIDs)}) } // flags, time, version; named, id counts
	const subdir = 0x80000000

	dir(len(types))
	off := typeDirsAt
	for _, t := range types {
		le([2]uint32{uint32(t.id), uint32(off) | subdir})
		off += dirSize + entSize*len(t.leaves)
	}
	nameDir := nameDirsAt
	for _, t := range types {
		dir(len(t.leaves))
		for _, l := range t.leaves {
			le([2]uint32{uint32(l.id), uint32(nameDir) | subdir})
			nameDir += dirSize + entSize
		}
	}
	dataEnt := dataEntsAt
	for _, t := range types {
		for range t.leaves {
			dir(1)
			le([2]uint32{langNeutral, uint32(dataEnt)})
			dataEnt += dataEntSize
		}
	}
	var relocs []uint32 // section offsets of the RVA fields
	data := dataAt
	for _, t := range types {
		for _, l := range t.leaves {
			relocs = append(relocs, uint32(sec.Len()))
			le([4]uint32{uint32(data), uint32(len(l.data)), 0, 0})
			data += (len(l.data) + 7) &^ 7
		}
	}
	for _, t := range types {
		for _, l := range t.leaves {
			sec.Write(l.data)
			sec.Write(make([]byte, (8-len(l.data)%8)%8))
		}
	}

	const fileHdr, secHdr, relocSize = 20, 40, 10
	rawAt := fileHdr + secHdr
	relocAt := rawAt + sec.Len()
	symAt := relocAt + relocSize*len(relocs)

	var o bytes.Buffer
	w := func(v any) { binary.Write(&o, binary.LittleEndian, v) }
	// IMAGE_FILE_HEADER: AMD64, 1 section, 1 symbol, no optional header.
	w(uint16(0x8664))
	w(uint16(1))
	w(uint32(0))
	w(uint32(symAt))
	w(uint32(1))
	w(uint16(0))
	w(uint16(0))
	// IMAGE_SECTION_HEADER .rsrc: initialized data, readable.
	o.WriteString(".rsrc\x00\x00\x00")
	w([4]uint32{0, 0, uint32(sec.Len()), uint32(rawAt)})
	w([2]uint32{uint32(relocAt), 0})
	w([2]uint16{uint16(len(relocs)), 0})
	w(uint32(0x40000040))
	o.Write(sec.Bytes())
	for _, r := range relocs {
		w(r)         // VirtualAddress (offset in section)
		w(uint32(0)) // symbol index: .rsrc
		w(uint16(3)) // IMAGE_REL_AMD64_ADDR32NB
	}
	// Symbol .rsrc: value 0, section 1, static.
	o.WriteString(".rsrc\x00\x00\x00")
	w(uint32(0))
	w(int16(1))
	w(uint16(0))
	o.Write([]byte{3, 0})
	w(uint32(4)) // empty string table
	return o.Bytes()
}
