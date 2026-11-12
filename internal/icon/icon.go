// Package icon draws the KeyGate logo: a white key on a rounded square whose colour is the state.
// The same geometry feeds the tray (per state), the Windows exe icon, the PWA icons and the SVG logo.
package icon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
)

// States and their colours (locked grey, unlocked blue, work session green, pending request amber).
var colors = map[string]color.NRGBA{
	"locked":   {0x6B, 0x72, 0x80, 0xFF},
	"unlocked": {0x25, 0x63, 0xEB, 0xFF},
	"session":  {0x16, 0xA3, 0x4A, 0xFF},
	"pending":  {0xD9, 0x77, 0x06, 0xFF},
}

// Brand is the state whose colour is the app/logo colour (exe, PWA, docs).
const Brand = "unlocked"

// Geometry in units of the icon side. The key is drawn in its own frame (u along the shaft towards
// the tip, v towards the teeth), centred at (keyCX, 0.5) and turned -45° so the tip points up-right.
const (
	cornerR = 0.22 // background corner radius
	keyCX   = 0.477
	bowU    = -0.18 // bow (ring) centre
	bowR    = 0.165
	holeR   = 0.07
	shaftU0 = -0.03
	shaftU1 = 0.36
	shaftHW = 0.052 // shaft half width
)

// teeth are [u0, u1, v1] boxes hanging from the shaft (v from 0 to v1).
var teeth = [][3]float64{{0.22, 0.28, 0.15}, {0.31, 0.36, 0.12}}

// Style selects the background shape and glyph size.
type Style struct {
	Maskable bool // full-bleed square, glyph shrunk into the 80% safe zone (PWA "maskable")
}

func (s Style) radius() float64 {
	if s.Maskable {
		return 0
	}
	return cornerR
}

func (s Style) scale() float64 {
	if s.Maskable {
		return 0.72
	}
	return 1
}

// Image returns the size x size icon for state (unknown state = locked).
func Image(size int, state string) *image.NRGBA { return Render(size, state, Style{}) }

// Render draws the icon with the given style.
func Render(size int, state string, st Style) *image.NRGBA {
	c, ok := colors[state]
	if !ok {
		c = colors["locked"]
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	n := float64(size)
	r, k := st.radius(), st.scale()
	const ss = 6 // supersampling per axis
	for y := range size {
		for x := range size {
			bg, fg := 0, 0
			for sy := range ss {
				for sx := range ss {
					px := (float64(x) + (float64(sx)+0.5)/ss) / n
					py := (float64(y) + (float64(sy)+0.5)/ss) / n
					if !inRounded(px, py, r) {
						continue
					}
					bg++
					if inKey(px, py, k) {
						fg++
					}
				}
			}
			if bg == 0 {
				continue
			}
			// Premultiplied mix of white (fg samples) and the state colour, then un-premultiply.
			mix := func(ch uint8) uint8 { return uint8((fg*255 + (bg-fg)*int(ch) + bg/2) / bg) }
			img.SetNRGBA(x, y, color.NRGBA{mix(c.R), mix(c.G), mix(c.B), uint8(bg * 255 / (ss * ss))})
		}
	}
	return img
}

// inRounded reports whether (x, y) in [0,1]² lies in the square with corner radius r.
func inRounded(x, y, r float64) bool {
	cx, cy := x, y
	switch {
	case x < r:
		cx = r
	case x > 1-r:
		cx = 1 - r
	}
	switch {
	case y < r:
		cy = r
	case y > 1-r:
		cy = 1 - r
	}
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= r*r
}

// inKey reports whether (x, y) in [0,1]² lies on the key glyph scaled by k around its centre.
func inKey(x, y, k float64) bool {
	dx, dy := (x-keyCX)/k, (y-0.5)/k
	u, v := (dx-dy)/math.Sqrt2, (dx+dy)/math.Sqrt2
	if d := math.Hypot(u-bowU, v); d <= bowR {
		return d > holeR
	}
	if u >= shaftU0 && u <= shaftU1 && math.Abs(v) <= shaftHW {
		return true
	}
	for _, t := range teeth {
		if u >= t[0] && u <= t[1] && v >= 0 && v <= t[2] {
			return true
		}
	}
	return false
}

// SVG returns the same icon as a 100x100 SVG document.
func SVG(state string, st Style) string {
	c, ok := colors[state]
	if !ok {
		c = colors["locked"]
	}
	f := func(v float64) string { return fmt.Sprintf("%.4g", v*100) }
	var b bytes.Buffer
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" role="img" aria-label="KeyGate">`+"\n")
	fmt.Fprintf(&b, `<rect width="100" height="100" rx="%s" fill="#%02X%02X%02X"/>`+"\n", f(st.radius()), c.R, c.G, c.B)
	fmt.Fprintf(&b, `<g fill="#FFFFFF" transform="translate(%s 50) rotate(-45) scale(%.4g)">`+"\n", f(keyCX), st.scale())
	fmt.Fprintf(&b, `<path fill-rule="evenodd" d="M%s 0a%s %s 0 1 0 %s 0a%s %s 0 1 0 -%s 0ZM%s 0a%s %s 0 1 0 %s 0a%s %s 0 1 0 -%s 0Z"/>`+"\n",
		f(bowU-bowR), f(bowR), f(bowR), f(2*bowR), f(bowR), f(bowR), f(2*bowR),
		f(bowU-holeR), f(holeR), f(holeR), f(2*holeR), f(holeR), f(holeR), f(2*holeR))
	fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s"/>`+"\n", f(shaftU0), f(-shaftHW), f(shaftU1-shaftU0), f(2*shaftHW))
	for _, t := range teeth {
		fmt.Fprintf(&b, `<rect x="%s" y="0" width="%s" height="%s"/>`+"\n", f(t[0]), f(t[1]-t[0]), f(t[2]))
	}
	b.WriteString("</g>\n</svg>\n")
	return b.String()
}

// PNG encodes Image.
func PNG(size int, state string) []byte { return EncodePNG(Image(size, state)) }

// EncodePNG encodes img as PNG.
func EncodePNG(img image.Image) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		panic(err) // encoding an in-memory image cannot fail
	}
	return b.Bytes()
}

// BGRA returns the pixels as premultiplied top-down BGRA (fallback for CreateIconIndirect).
func BGRA(size int, state string) []byte {
	img := Image(size, state)
	out := make([]byte, 0, size*size*4)
	for i := 0; i < len(img.Pix); i += 4 {
		a := uint32(img.Pix[i+3])
		out = append(out, byte(uint32(img.Pix[i+2])*a/255), byte(uint32(img.Pix[i+1])*a/255), byte(uint32(img.Pix[i])*a/255), byte(a))
	}
	return out
}

// IconImage is one image of a Windows icon: its side and its resource bytes (DIB below 256, PNG at 256).
type IconImage struct {
	Size int
	Data []byte
}

// IconImages renders state at each size in the format Windows expects inside .ico / RT_ICON.
func IconImages(state string, sizes ...int) []IconImage {
	out := make([]IconImage, 0, len(sizes))
	for _, s := range sizes {
		img := Image(s, state)
		if s >= 256 {
			out = append(out, IconImage{s, EncodePNG(img)})
			continue
		}
		out = append(out, IconImage{s, dib(img)})
	}
	return out
}

// dib encodes img as a 32-bit icon DIB: BITMAPINFOHEADER (double height), bottom-up straight BGRA,
// then an all-zero 1-bit AND mask (alpha carries transparency).
func dib(img *image.NRGBA) []byte {
	s := img.Rect.Dx()
	maskRow := (s + 31) / 32 * 4
	var b bytes.Buffer
	hdr := struct {
		Size                   uint32
		Width, Height          int32
		Planes, BitCount       uint16
		Compression, SizeImage uint32
		XPels, YPels           int32
		ClrUsed, ClrImportant  uint32
	}{40, int32(s), int32(2 * s), 1, 32, 0, uint32(s*s*4 + maskRow*s), 0, 0, 0, 0}
	binary.Write(&b, binary.LittleEndian, hdr)
	for y := s - 1; y >= 0; y-- {
		row := img.Pix[y*img.Stride : y*img.Stride+s*4]
		for i := 0; i < len(row); i += 4 {
			b.Write([]byte{row[i+2], row[i+1], row[i], row[i+3]})
		}
	}
	b.Write(make([]byte, maskRow*s))
	return b.Bytes()
}

// GroupEntry is the 8-byte head shared by ICONDIRENTRY (.ico) and GRPICONDIRENTRY (RT_GROUP_ICON).
func GroupEntry(im IconImage) []byte {
	w := byte(im.Size) // 256 is written as 0
	var b bytes.Buffer
	b.Write([]byte{w, w, 0, 0})
	binary.Write(&b, binary.LittleEndian, [2]uint16{1, 32})
	return b.Bytes()
}

// ICO encodes images as a .ico file.
func ICO(images []IconImage) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, 1, uint16(len(images))})
	off := 6 + 16*len(images)
	for _, im := range images {
		b.Write(GroupEntry(im))
		binary.Write(&b, binary.LittleEndian, [2]uint32{uint32(len(im.Data)), uint32(off)})
		off += len(im.Data)
	}
	for _, im := range images {
		b.Write(im.Data)
	}
	return b.Bytes()
}
