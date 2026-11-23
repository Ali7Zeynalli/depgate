// Command winres writes the Windows resources of depgate.exe: the version
// information Explorer shows under Properties > Details (product, version,
// author) and the program icon. The release build runs it before building:
//
//	go run ./tools/winres -version 0.23.0
//
// It writes rsrc_windows_amd64.syso and rsrc_windows_arm64.syso next to
// main.go; the Go toolchain links a .syso of the target platform by itself.
// Standard library only: a COFF object with one .rsrc section.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

func main() {
	version := flag.String("version", "0.0.0", "product version (x.y.z)")
	out := flag.String("out", ".", "folder for the .syso files")
	flag.Parse()
	icon, err := iconPNG(256)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winres:", err)
		os.Exit(1)
	}
	res := []resource{
		{typ: 3, id: 1, data: icon},                                            // RT_ICON
		{typ: 14, id: 1, data: groupIcon(len(icon))},                           // RT_GROUP_ICON
		{typ: 16, id: 1, data: versionInfo(strings.TrimPrefix(*version, "v"))}, // RT_VERSION
	}
	for _, m := range []struct {
		arch    string
		machine uint16
		reloc   uint16
	}{{"amd64", 0x8664, 3}, {"arm64", 0xAA64, 2}} {
		b := coff(m.machine, m.reloc, res)
		p := filepath.Join(*out, "rsrc_windows_"+m.arch+".syso")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "winres:", err)
			os.Exit(1)
		}
	}
}

type resource struct {
	typ, id uint32
	data    []byte
}

const lang = 0x0409 // en-US

// coff lays out a resource directory (type > id > language > data) in a
// .rsrc section; each data entry's address is relocated by the linker.
func coff(machine, relocType uint16, res []resource) []byte {
	sort.Slice(res, func(i, j int) bool { return res[i].typ < res[j].typ })
	le := binary.LittleEndian
	var sec bytes.Buffer
	// sizes: root dir + per type (dir) + per type (lang dir), then data entries, then data
	nt := len(res)
	rootSize := 16 + 8*nt
	idDirSize := 16 + 8   // one id under each type
	langDirSize := 16 + 8 // one language under each id
	idDirs := rootSize
	langDirs := idDirs + nt*idDirSize
	entries := langDirs + nt*langDirSize
	dataStart := entries + nt*16
	dataOff := make([]int, nt)
	off := align(dataStart, 8)
	for i, r := range res {
		dataOff[i] = off
		off = align(off+len(r.data), 8)
	}
	hdr := func(ids int) {
		binary.Write(&sec, le, uint32(0))
		binary.Write(&sec, le, uint32(0))
		binary.Write(&sec, le, uint16(0))
		binary.Write(&sec, le, uint16(0))
		binary.Write(&sec, le, uint16(0))
		binary.Write(&sec, le, uint16(ids))
	}
	hdr(nt)
	for i, r := range res {
		binary.Write(&sec, le, r.typ)
		binary.Write(&sec, le, uint32(0x80000000|(idDirs+i*idDirSize)))
	}
	for i, r := range res {
		hdr(1)
		binary.Write(&sec, le, r.id)
		binary.Write(&sec, le, uint32(0x80000000|(langDirs+i*langDirSize)))
	}
	for i := range res {
		hdr(1)
		binary.Write(&sec, le, uint32(lang))
		binary.Write(&sec, le, uint32(entries+i*16))
	}
	var relocs []int
	for i, r := range res {
		relocs = append(relocs, sec.Len())
		binary.Write(&sec, le, uint32(dataOff[i])) // + section RVA (relocation)
		binary.Write(&sec, le, uint32(len(r.data)))
		binary.Write(&sec, le, uint32(0))
		binary.Write(&sec, le, uint32(0))
	}
	for i, r := range res {
		for sec.Len() < dataOff[i] {
			sec.WriteByte(0)
		}
		sec.Write(r.data)
	}
	for sec.Len()%8 != 0 {
		sec.WriteByte(0)
	}

	const fileHdr, secHdr = 20, 40
	raw := fileHdr + secHdr
	relocAt := raw + sec.Len()
	symAt := relocAt + 10*len(relocs)
	var b bytes.Buffer
	binary.Write(&b, le, machine)
	binary.Write(&b, le, uint16(1))
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, uint32(symAt))
	binary.Write(&b, le, uint32(1))
	binary.Write(&b, le, uint16(0))
	binary.Write(&b, le, uint16(0))
	b.WriteString(".rsrc\x00\x00\x00")
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, uint32(sec.Len()))
	binary.Write(&b, le, uint32(raw))
	binary.Write(&b, le, uint32(relocAt))
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, uint16(len(relocs)))
	binary.Write(&b, le, uint16(0))
	binary.Write(&b, le, uint32(0x40000040)) // initialized data, readable
	b.Write(sec.Bytes())
	for _, r := range relocs {
		binary.Write(&b, le, uint32(r))
		binary.Write(&b, le, uint32(0)) // symbol 0: the section
		binary.Write(&b, le, relocType)
	}
	b.WriteString(".rsrc\x00\x00\x00")
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, uint16(1))
	binary.Write(&b, le, uint16(0))
	b.WriteByte(3) // static
	b.WriteByte(0)
	binary.Write(&b, le, uint32(4)) // empty string table
	return b.Bytes()
}

func align(n, a int) int { return (n + a - 1) / a * a }

// ---------- VS_VERSIONINFO ----------

func wstr(s string) []byte {
	var b bytes.Buffer
	for _, u := range utf16.Encode([]rune(s)) {
		binary.Write(&b, binary.LittleEndian, u)
	}
	b.Write([]byte{0, 0})
	return b.Bytes()
}

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

// block is one node: wLength, wValueLength, wType, key, value, children.
func block(key string, value []byte, valueLen uint16, text bool, children ...[]byte) []byte {
	var b bytes.Buffer
	b.Write(make([]byte, 6))
	b.Write(wstr(key))
	pad4(&b)
	b.Write(value)
	for _, c := range children {
		pad4(&b)
		b.Write(c)
	}
	out := b.Bytes()
	le := binary.LittleEndian
	le.PutUint16(out[0:], uint16(len(out)))
	le.PutUint16(out[2:], valueLen)
	if text {
		le.PutUint16(out[4:], 1)
	}
	return out
}

func versionInfo(v string) []byte {
	n := [4]uint16{}
	for i, p := range strings.SplitN(strings.SplitN(v, "-", 2)[0], ".", 4) {
		x, _ := strconv.Atoi(p)
		n[i] = uint16(x)
	}
	le := binary.LittleEndian
	var fixed bytes.Buffer
	for _, x := range []uint32{0xFEEF04BD, 0x00010000,
		uint32(n[0])<<16 | uint32(n[1]), uint32(n[2])<<16 | uint32(n[3]),
		uint32(n[0])<<16 | uint32(n[1]), uint32(n[2])<<16 | uint32(n[3]),
		0x3F, 0, 0x00040004, 1, 0, 0, 0} {
		binary.Write(&fixed, le, x)
	}
	str := func(k, val string) []byte {
		w := wstr(val)
		return block(k, w, uint16(len(w)/2), true)
	}
	table := block("040904B0", nil, 0, true,
		str("CompanyName", "Ali Zeynalli"),
		str("FileDescription", "DepGate: dependency and Docker security advisor"),
		str("FileVersion", v),
		str("InternalName", "depgate"),
		str("LegalCopyright", "Copyright (c) Ali Zeynalli. MIT License."),
		str("OriginalFilename", "depgate.exe"),
		str("ProductName", "DepGate"),
		str("ProductVersion", v),
		str("Comments", "https://github.com/Ali7Zeynalli/depgate"))
	var tr bytes.Buffer
	binary.Write(&tr, le, uint16(lang))
	binary.Write(&tr, le, uint16(0x04B0)) // Unicode
	return block("VS_VERSION_INFO", fixed.Bytes(), uint16(fixed.Len()), false,
		block("StringFileInfo", nil, 0, true, table),
		block("VarFileInfo", nil, 0, true, block("Translation", tr.Bytes(), 4, false)))
}

// ---------- the icon: the shield and tick of the page's logo ----------

func groupIcon(size int) []byte {
	var b bytes.Buffer
	le := binary.LittleEndian
	binary.Write(&b, le, [3]uint16{0, 1, 1}) // reserved, type icon, one image
	b.Write([]byte{0, 0, 0, 0})              // 256 x 256, no palette
	binary.Write(&b, le, uint16(1))          // planes
	binary.Write(&b, le, uint16(32))         // bits
	binary.Write(&b, le, uint32(size))
	binary.Write(&b, le, uint16(1)) // RT_ICON id
	return b.Bytes()
}

func iconPNG(n int) ([]byte, error) {
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	s := float64(n) / 256
	bg := color.NRGBA{0x18, 0x18, 0x1b, 0xff}
	fg := color.NRGBA{0xff, 0xff, 0xff, 0xff}
	// coverage of a rounded square, a shield outline and a tick, sampled 4x4 per pixel
	shield := []pt{{128, 52}, {192, 80}, {192, 128}, {186, 166}, {164, 194}, {128, 214}, {92, 194}, {70, 166}, {64, 128}, {64, 80}, {128, 52}}
	tick := []pt{{100, 132}, {120, 152}, {158, 112}}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			var cb, cf float64
			for sy := 0; sy < 4; sy++ {
				for sx := 0; sx < 4; sx++ {
					px := (float64(x) + (float64(sx)+.5)/4) / s
					py := (float64(y) + (float64(sy)+.5)/4) / s
					if inRound(px, py, 8, 248, 56) {
						cb++
						if nearPath(px, py, shield, 9) || nearPath(px, py, tick, 11) {
							cf++
						}
					}
				}
			}
			if cb == 0 {
				continue
			}
			a := cb / 16
			t := cf / math.Max(cb, 1)
			mix := func(a1, b1 uint8) uint8 { return uint8(float64(a1)*(1-t) + float64(b1)*t + .5) }
			img.SetNRGBA(x, y, color.NRGBA{mix(bg.R, fg.R), mix(bg.G, fg.G), mix(bg.B, fg.B), uint8(a*255 + .5)})
		}
	}
	var b bytes.Buffer
	err := png.Encode(&b, img)
	return b.Bytes(), err
}

type pt struct{ x, y float64 }

func inRound(x, y, lo, hi, r float64) bool {
	cx := math.Max(lo+r, math.Min(x, hi-r))
	cy := math.Max(lo+r, math.Min(y, hi-r))
	return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= r*r && x >= lo && x <= hi && y >= lo && y <= hi
}

func nearPath(x, y float64, ps []pt, w float64) bool {
	for i := 1; i < len(ps); i++ {
		a, b := ps[i-1], ps[i]
		dx, dy := b.x-a.x, b.y-a.y
		t := ((x-a.x)*dx + (y-a.y)*dy) / (dx*dx + dy*dy)
		t = math.Max(0, math.Min(1, t))
		qx, qy := a.x+t*dx-x, a.y+t*dy-y
		if qx*qx+qy*qy <= w*w {
			return true
		}
	}
	return false
}
