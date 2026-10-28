// Decoding as quiche (patch 0028).

package hpack

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// quicheDecode decodes block with SetQuicheErrors and a maximum string
// length of max, and returns the fields and the error of Write or Close.
func quicheDecode(block []byte, max int, emit bool) ([]HeaderField, error) {
	var got []HeaderField
	d := NewDecoder(4096, func(f HeaderField) { got = append(got, f) })
	d.SetQuicheErrors(true)
	d.SetMaxStringLength(max)
	d.SetEmitEnabled(emit)
	if _, err := d.Write(block); err != nil {
		return got, err
	}
	return got, d.Close()
}

// The maximum string length limits the encoded length only: a Huffman
// value longer once decoded is accepted, and one longer encoded is not.
func TestQuicheStringLength(t *testing.T) {
	var b bytes.Buffer
	NewEncoder(&b).WriteField(HeaderField{Name: "a", Value: strings.Repeat("a", 12)}) // 8 bytes in Huffman
	got, err := quicheDecode(b.Bytes(), 10, true)
	if err != nil || len(got) != 1 || len(got[0].Value) != 12 {
		t.Errorf("got %v, %v", got, err)
	}
	if _, err := quicheDecode(b.Bytes(), 7, true); err != QuicheValueTooLong {
		t.Errorf("max 7: %v, want %v", err, QuicheValueTooLong)
	}
}

// Every Huffman string is decoded, even with the emit disabled.
func TestQuicheHuffmanNotEmitted(t *testing.T) {
	if _, err := quicheDecode([]byte{0x00, 0x01, 'a', 0x81, 0x00}, 0, false); err != QuicheValueHuffmanError {
		t.Errorf("%v, want %v", err, QuicheValueHuffmanError)
	}
}

// An integer may take ten bytes after its prefix: an index of 127 so
// written is an invalid index, not an integer error.
func TestQuicheVarint(t *testing.T) {
	block := append([]byte{0xff}, bytes.Repeat([]byte{0x80}, 9)...)
	if _, err := quicheDecode(append(block, 0x00), 0, true); err != QuicheInvalidIndex {
		t.Errorf("%v, want %v", err, QuicheInvalidIndex)
	}
	if _, err := quicheDecode(append(block, 0x01), 0, true); err != QuicheIndexVarintError {
		t.Errorf("1<<63: %v, want %v", err, QuicheIndexVarintError)
	}
}

// The errors are named as in Chromium's debug data.
func TestQuicheErrorName(t *testing.T) {
	err := error(QuicheTruncatedBlock)
	var qe QuicheError
	if !errors.As(err, &qe) || qe.Name() != "HPACK_TRUNCATED_BLOCK" || err.Error() != "hpack: HPACK_TRUNCATED_BLOCK" {
		t.Errorf("%v", err)
	}
}

// The size updates are counted in each header block: two may start the
// next block, after a block with two, or with a field.
func TestQuicheSizeUpdatePerBlock(t *testing.T) {
	d := NewDecoder(4096, func(HeaderField) {})
	d.SetQuicheErrors(true)
	for i, block := range [][]byte{{0x20, 0x20}, {0x20, 0x20, 0x88}, {0x20, 0x20, 0x88}} {
		if _, err := d.Write(block); err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		if err := d.Close(); err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
	}
}
