// Package qr encodes short byte strings (pairing links) as QR Code Model 2 symbols: byte mode,
// error-correction level M, versions 1-10 (up to 213 bytes). Only what `kgw tray` needs to show a
// pairing link; no third-party dependency (repo rule: stdlib + x/crypto + x/sys).
package qr

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
)

// ErrTooLong means the data does not fit a version-10-M symbol.
var ErrTooLong = errors.New("qr: dữ liệu quá dài")

// Code is an encoded symbol; Dark(x, y) reports module colour (x = column, y = row).
type Code struct {
	Size    int
	modules [][]bool
}

// Dark reports whether module (x, y) is dark.
func (c *Code) Dark(x, y int) bool { return c.modules[y][x] }

type block struct{ count, data int }

// level-M parameters per version: EC codewords per block and the block groups.
var levelM = [11]struct {
	ec     int
	groups []block
}{
	{},
	{10, []block{{1, 16}}},
	{16, []block{{1, 28}}},
	{26, []block{{1, 44}}},
	{18, []block{{2, 32}}},
	{24, []block{{2, 43}}},
	{16, []block{{4, 27}}},
	{18, []block{{4, 31}}},
	{22, []block{{2, 38}, {2, 39}}},
	{22, []block{{3, 36}, {2, 37}}},
	{26, []block{{4, 43}, {1, 44}}},
}

var alignPos = [11][]int{nil, nil, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50}}

func dataCodewords(v int) int {
	n := 0
	for _, g := range levelM[v].groups {
		n += g.count * g.data
	}
	return n
}

func countBits(v int) int {
	if v < 10 {
		return 8
	}
	return 16
}

// Encode returns the smallest symbol holding data, with the lowest-penalty mask.
func Encode(data []byte) (*Code, error) {
	ver := 0
	for v := 1; v <= 10; v++ {
		if 4+countBits(v)+8*len(data) <= 8*dataCodewords(v) {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, ErrTooLong
	}
	// bit stream: mode 0100, count, bytes, terminator, byte pad, 0xEC/0x11 pad
	var bits []bool
	put := func(val, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (val>>i)&1 == 1)
		}
	}
	put(4, 4)
	put(len(data), countBits(ver))
	for _, b := range data {
		put(int(b), 8)
	}
	capBits := 8 * dataCodewords(ver)
	for i := 0; i < 4 && len(bits) < capBits; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	for pad := 0xEC; len(bits) < capBits; pad ^= 0xEC ^ 0x11 {
		put(pad, 8)
	}
	cw := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			cw[i/8] |= 0x80 >> (i % 8)
		}
	}

	// split into blocks, add Reed-Solomon EC, interleave
	ec := levelM[ver].ec
	div := rsDivisor(ec)
	var dataBlocks, ecBlocks [][]byte
	off := 0
	for _, g := range levelM[ver].groups {
		for range g.count {
			d := cw[off : off+g.data]
			off += g.data
			dataBlocks = append(dataBlocks, d)
			ecBlocks = append(ecBlocks, rsRemainder(d, div))
		}
	}
	var final []byte
	longest := len(dataBlocks[len(dataBlocks)-1]) // groups are ordered by ascending block length
	for i := range longest {
		for _, d := range dataBlocks {
			if i < len(d) {
				final = append(final, d[i])
			}
		}
	}
	for i := range ec {
		for _, e := range ecBlocks {
			final = append(final, e[i])
		}
	}

	base := newMatrix(ver)
	base.drawCodewords(final)
	var best *matrix
	bestPen := -1
	for mask := range 8 {
		m := base.clone()
		m.applyMask(mask)
		m.drawFormat(mask)
		if p := m.penalty(); bestPen < 0 || p < bestPen {
			best, bestPen = m, p
		}
	}
	return &Code{Size: best.size, modules: best.mod}, nil
}

// PNG renders the symbol with a 4-module quiet zone, scale pixels per module.
func (c *Code) PNG(scale int) []byte {
	n := (c.Size + 8) * scale
	img := image.NewGray(image.Rect(0, 0, n, n))
	for i := range img.Pix {
		img.Pix[i] = 0xFF
	}
	for y := range c.Size {
		for x := range c.Size {
			if !c.modules[y][x] {
				continue
			}
			for dy := range scale {
				for dx := range scale {
					img.SetGray((x+4)*scale+dx, (y+4)*scale+dy, color.Gray{})
				}
			}
		}
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img) // in-memory encode of a valid image cannot fail
	return b.Bytes()
}

type matrix struct {
	ver, size int
	mod, fn   [][]bool // fn = function module (not data, not masked)
}

func newMatrix(ver int) *matrix {
	s := ver*4 + 17
	m := &matrix{ver: ver, size: s}
	m.mod, m.fn = make([][]bool, s), make([][]bool, s)
	for i := range m.mod {
		m.mod[i], m.fn[i] = make([]bool, s), make([]bool, s)
	}
	for i := range s { // timing patterns
		m.set(6, i, i%2 == 0)
		m.set(i, 6, i%2 == 0)
	}
	m.finder(3, 3)
	m.finder(s-4, 3)
	m.finder(3, s-4)
	ap := alignPos[ver]
	for i, a := range ap {
		for j, b := range ap {
			if (i == 0 && j == 0) || (i == 0 && j == len(ap)-1) || (i == len(ap)-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					m.set(a+dx, b+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	m.drawFormat(0) // reserve format areas (rewritten per mask)
	if ver >= 7 {
		rem := ver
		for range 12 {
			rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
		}
		bits := ver<<12 | rem
		for i := range 18 {
			bit := (bits>>i)&1 == 1
			a, b := s-11+i%3, i/3
			m.set(a, b, bit)
			m.set(b, a, bit)
		}
	}
	return m
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (m *matrix) set(x, y int, dark bool) {
	m.mod[y][x] = dark
	m.fn[y][x] = true
}

func (m *matrix) finder(cx, cy int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			x, y := cx+dx, cy+dy
			if x < 0 || y < 0 || x >= m.size || y >= m.size {
				continue
			}
			d := max(abs(dx), abs(dy))
			m.set(x, y, d != 2 && d != 4)
		}
	}
}

func (m *matrix) drawFormat(mask int) {
	data := 0<<3 | mask // level M = 00
	rem := data
	for range 10 {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	bits := (data<<10 | rem) ^ 0x5412
	b := func(i int) bool { return (bits>>i)&1 == 1 }
	for i := 0; i <= 5; i++ {
		m.set(8, i, b(i))
	}
	m.set(8, 7, b(6))
	m.set(8, 8, b(7))
	m.set(7, 8, b(8))
	for i := 9; i < 15; i++ {
		m.set(14-i, 8, b(i))
	}
	for i := range 8 {
		m.set(m.size-1-i, 8, b(i))
	}
	for i := 8; i < 15; i++ {
		m.set(8, m.size-15+i, b(i))
	}
	m.set(8, m.size-8, true) // dark module
}

func (m *matrix) drawCodewords(data []byte) {
	i := 0
	for right := m.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := range m.size {
			for j := range 2 {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = m.size - 1 - vert
				}
				if !m.fn[y][x] && i < len(data)*8 {
					m.mod[y][x] = (data[i>>3]>>(7-uint(i&7)))&1 == 1
					i++
				}
			}
		}
	}
}

func (m *matrix) clone() *matrix {
	c := &matrix{ver: m.ver, size: m.size, mod: make([][]bool, m.size), fn: m.fn}
	for i := range m.mod {
		c.mod[i] = append([]bool(nil), m.mod[i]...)
	}
	return c
}

func (m *matrix) applyMask(mask int) {
	for y := range m.size {
		for x := range m.size {
			if m.fn[y][x] {
				continue
			}
			var inv bool
			switch mask {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if inv {
				m.mod[y][x] = !m.mod[y][x]
			}
		}
	}
}

// penalty implements the four ISO/IEC 18004 mask evaluation rules.
func (m *matrix) penalty() int {
	s := m.size
	p := 0
	at := func(x, y int, row bool) bool {
		if row {
			return m.mod[y][x]
		}
		return m.mod[x][y]
	}
	finderLike := [][]bool{
		{true, false, true, true, true, false, true, false, false, false, false},
		{false, false, false, false, true, false, true, true, true, false, true},
	}
	for _, row := range []bool{true, false} {
		for a := range s {
			run := 1
			for b := 1; b <= s; b++ {
				if b < s && at(b, a, row) == at(b-1, a, row) {
					run++
					continue
				}
				if run >= 5 {
					p += 3 + run - 5
				}
				run = 1
			}
			for b := 0; b+11 <= s; b++ {
				for _, pat := range finderLike {
					ok := true
					for k := 0; k < 11 && ok; k++ {
						ok = at(b+k, a, row) == pat[k]
					}
					if ok {
						p += 40
					}
				}
			}
		}
	}
	dark := 0
	for y := range s {
		for x := range s {
			if m.mod[y][x] {
				dark++
			}
			if x+1 < s && y+1 < s {
				c := m.mod[y][x]
				if c == m.mod[y][x+1] && c == m.mod[y+1][x] && c == m.mod[y+1][x+1] {
					p += 3
				}
			}
		}
	}
	total := s * s
	k := (abs(dark*20-total*10) + total - 1) / total - 1
	if k > 0 {
		p += k * 10
	}
	return p
}

// GF(256) with polynomial 0x11D.
func gfMul(x, y byte) byte {
	var z byte
	for i := 7; i >= 0; i-- {
		hi := z & 0x80
		z <<= 1
		if hi != 0 {
			z ^= 0x1D
		}
		if (y>>uint(i))&1 == 1 {
			z ^= x
		}
	}
	return z
}

func rsDivisor(degree int) []byte {
	r := make([]byte, degree)
	r[degree-1] = 1
	root := byte(1)
	for range degree {
		for j := range r {
			r[j] = gfMul(r[j], root)
			if j+1 < len(r) {
				r[j] ^= r[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return r
}

func rsRemainder(data, div []byte) []byte {
	r := make([]byte, len(div))
	for _, b := range data {
		f := b ^ r[0]
		copy(r, r[1:])
		r[len(r)-1] = 0
		for i := range r {
			r[i] ^= gfMul(div[i], f)
		}
	}
	return r
}
