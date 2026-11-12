// gen-winres writes the Windows icon assets drawn by internal/icon:
//   - cmd/kg/rsrc_windows_amd64.syso: COFF object with RT_ICON + RT_GROUP_ICON (id 1); the Go linker
//     embeds it into kg.exe / kgw.exe, so Explorer, the taskbar and shortcuts show the logo;
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
	langNeutral = 0
	groupID     = 1
)

type leaf struct {
	id   uint16
	data []byte
}

// syso builds an AMD64 COFF object with one .rsrc section holding the icon images (ids 1..n) and
// one group icon (id groupID). Data-entry RVAs are section offsets fixed up by ADDR32NB relocations.
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
	}{{rtIcon, icons}, {rtGroupIcon, []leaf{{groupID, group.Bytes()}}}} // sorted by type id

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
