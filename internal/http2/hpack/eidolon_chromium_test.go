// HPACK encoding of Chromium (patch 0022).

package hpack

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// The representations of the Chrome 156 capture (A10): only :authority is
// indexed among the pseudo-headers, :path goes without indexing under the
// name of index 4, a regular field is indexed, and a name of the static
// table refers to its first entry; the default policy indexes :path under
// the name of index 5.
func TestChromiumPolicy(t *testing.T) {
	fields := []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "lab.test"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/style.css"},
		{Name: ":method", Value: "PUT"},
		{Name: "user-agent", Value: "Mozilla/5.0"},
		{Name: "sec-ch-ua-mobile", Value: "?0"},
		{Name: ":authority", Value: "lab.test"},
		{Name: ":path", Value: "/style.css"},
		{Name: "user-agent", Value: "Mozilla/5.0"},
		{Name: "authorization", Value: "secret", Sensitive: true},
	}
	for _, tt := range []struct {
		name     string
		chromium bool
		want     []byte
		table    []HeaderField // dynamic table, newest first
	}{
		{"chromium", true,
			[]byte{0x82, 0x41, 0x87, 0x04, 0x02, 0x7a, 0x40, 0xc0, 0x04, 0xbf, 0x1f},
			[]HeaderField{
				{Name: "sec-ch-ua-mobile", Value: "?0"},
				{Name: "user-agent", Value: "Mozilla/5.0"},
				{Name: ":authority", Value: "lab.test"},
			}},
		{"default", false,
			[]byte{0x82, 0x41, 0x87, 0x45, 0x43, 0x7a, 0x40, 0xc2, 0xc1, 0xbf, 0x1f},
			[]HeaderField{
				{Name: "sec-ch-ua-mobile", Value: "?0"},
				{Name: "user-agent", Value: "Mozilla/5.0"},
				{Name: ":method", Value: "PUT"},
				{Name: ":path", Value: "/style.css"},
				{Name: ":authority", Value: "lab.test"},
			}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf, all bytes.Buffer
			e := NewEncoder(&buf)
			e.SetChromiumPolicy(tt.chromium)
			var got []byte
			for _, f := range fields {
				buf.Reset()
				if err := e.WriteField(f); err != nil {
					t.Fatal(err)
				}
				got = append(got, buf.Bytes()[0])
				all.Write(buf.Bytes())
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("representations %x, want %x", got, tt.want)
			}
			var table []HeaderField
			for i := e.dynTab.table.len() - 1; i >= 0; i-- {
				table = append(table, e.dynTab.table.ents[i])
			}
			if !slices.Equal(table, tt.table) {
				t.Errorf("table %v, want %v", table, tt.table)
			}
			decoded, err := NewDecoder(4096, nil).DecodeFull(all.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(decoded, fields) {
				t.Errorf("decoded %v, want %v", decoded, fields)
			}
		})
	}
}

// A field larger than the table is still indexed under the Chromium
// policy, and empties the table, as for the decoder (RFC 7541 section
// 4.4); the default policy leaves it out of the table.
func TestChromiumPolicyLargeField(t *testing.T) {
	large := HeaderField{Name: "cookie", Value: strings.Repeat("a", 5000)}
	for _, tt := range []struct {
		chromium bool
		first    byte
		table    int
	}{{true, 0x60, 0}, {false, 0x0f, 1}} {
		var buf bytes.Buffer
		e := NewEncoder(&buf)
		e.SetChromiumPolicy(tt.chromium)
		d := NewDecoder(4096, nil)
		e.WriteField(HeaderField{Name: ":authority", Value: "lab.test"})
		block := slices.Clone(buf.Bytes())
		buf.Reset()
		e.WriteField(large)
		block = append(block, buf.Bytes()...)
		if first := buf.Bytes()[0]; first != tt.first {
			t.Errorf("chromium %v: representation %x, want %x", tt.chromium, first, tt.first)
		}
		if n := e.dynTab.table.len(); n != tt.table {
			t.Errorf("chromium %v: %d entries, want %d", tt.chromium, n, tt.table)
		}
		// The decoder agrees: the next :authority is literal again, or
		// indexed.
		buf.Reset()
		e.WriteField(HeaderField{Name: ":authority", Value: "lab.test"})
		block = append(block, buf.Bytes()...)
		got, err := d.DecodeFull(block)
		if err != nil || len(got) != 3 || got[2].Value != "lab.test" {
			t.Errorf("chromium %v: decoded %v, %v", tt.chromium, got, err)
		}
	}
}

// The table takes the size the peer announces as quiche does: no update
// for the size in force, any size adopted, and the smallest size a
// setting lowered to before the final one; the default encoder sends an
// update even for the size in force and stops at its limit.
func TestApplyHeaderTableSizeSetting(t *testing.T) {
	for _, tt := range []struct {
		name     string
		settings []uint32
		want     string // hex of the size updates before the next field
		max      uint32
	}{
		{"same", []uint32{4096}, "", 4096},
		{"larger", []uint32{65536}, "3fe1ff03", 65536},
		{"smaller", []uint32{0}, "20", 0},
		{"lowered then raised", []uint32{100, 8000}, "3f453fa13e", 8000},
		{"raised twice", []uint32{8000, 9000}, "3f8946", 9000},
		{"raised then back", []uint32{8000, 4096}, "3fe11f", 4096},
		{"back to the start", []uint32{100, 4096}, "3f453fe11f", 4096},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			e := NewEncoder(&buf)
			e.SetChromiumPolicy(true)
			for _, v := range tt.settings {
				e.ApplyHeaderTableSizeSetting(v)
			}
			e.WriteField(HeaderField{Name: ":method", Value: "GET"})
			b := buf.Bytes()
			if got := hex.EncodeToString(b[:len(b)-1]); got != tt.want || b[len(b)-1] != 0x82 {
				t.Errorf("block %x, want %s82", b, tt.want)
			}
			if e.MaxDynamicTableSize() != tt.max {
				t.Errorf("table size %d, want %d", e.MaxDynamicTableSize(), tt.max)
			}
			buf.Reset()
			e.WriteField(HeaderField{Name: ":method", Value: "GET"})
			if !bytes.Equal(buf.Bytes(), []byte{0x82}) {
				t.Errorf("second block %x, want 82", buf.Bytes())
			}
		})
	}
	var buf bytes.Buffer
	e := NewEncoder(&buf)
	e.SetMaxDynamicTableSize(4096)
	e.SetMaxDynamicTableSize(65536)
	e.WriteField(HeaderField{Name: ":method", Value: "GET"})
	if got := hex.EncodeToString(buf.Bytes()); got != "3fe11f82" {
		t.Errorf("default encoder: block %s, want 3fe11f82", got)
	}
}
