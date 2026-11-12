package icon

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"image/png"
	"io"
	"testing"
)

func TestPNG(t *testing.T) {
	for _, st := range []string{"locked", "unlocked", "session", "pending"} {
		img, err := png.Decode(bytes.NewReader(PNG(32, st)))
		if err != nil || img.Bounds().Dx() != 32 {
			t.Fatalf("%s: %v", st, err)
		}
		c := colors[st]
		// Background (left edge, mid height) carries the state colour; the shaft near the centre is white.
		if r, g, b, a := img.At(4, 16).RGBA(); a != 0xFFFF || uint8(r>>8) != c.R || uint8(g>>8) != c.G || uint8(b>>8) != c.B {
			t.Fatalf("%s background %v %v %v %v", st, r>>8, g>>8, b>>8, a>>8)
		}
		if r, g, b, _ := img.At(15, 16).RGBA(); r>>8 != 0xFF || g>>8 != 0xFF || b>>8 != 0xFF {
			t.Fatalf("%s glyph not white: %v %v %v", st, r>>8, g>>8, b>>8)
		}
		if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
			t.Fatalf("%s corner not transparent", st)
		}
	}
	if len(BGRA(16, "session")) != 16*16*4 {
		t.Fatal("bgra size")
	}
	// Maskable is full bleed: the corner is opaque.
	if Render(64, Brand, Style{Maskable: true}).NRGBAAt(0, 0).A != 0xFF {
		t.Fatal("maskable corner transparent")
	}
}

func TestICO(t *testing.T) {
	ico := ICO(IconImages(Brand, 16, 32, 256))
	var hdr [3]uint16
	binary.Read(bytes.NewReader(ico), binary.LittleEndian, &hdr)
	if hdr != [3]uint16{0, 1, 3} {
		t.Fatalf("header %v", hdr)
	}
	for i, want := range []int{16, 32, 256} {
		e := ico[6+16*i:]
		size := int(binary.LittleEndian.Uint32(e[8:]))
		off := int(binary.LittleEndian.Uint32(e[12:]))
		if w := int(e[0]); w != want%256 || off+size > len(ico) {
			t.Fatalf("entry %d: width %d off %d size %d", i, w, off, size)
		}
		data := ico[off : off+size]
		if want == 256 {
			if _, err := png.Decode(bytes.NewReader(data)); err != nil {
				t.Fatalf("256 not PNG: %v", err)
			}
			continue
		}
		if h := int32(binary.LittleEndian.Uint32(data[8:])); h != int32(2*want) || size != 40+want*want*4+(want+31)/32*4*want {
			t.Fatalf("dib %d: height %d size %d", want, h, size)
		}
	}
}

func TestSVG(t *testing.T) {
	d := xml.NewDecoder(bytes.NewReader([]byte(SVG(Brand, Style{}))))
	for {
		if _, err := d.Token(); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			return
		}
	}
}
