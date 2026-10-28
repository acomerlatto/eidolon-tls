package hpack

import (
	"bytes"
	"errors"
	"fmt"
	"math"
)

// [eidolon] QuicheError is a decoding error of the Decoder with
// SetQuicheErrors, as quiche's HpackDecoder reports it to Chromium: the
// value is the number of its SpdyFramerError (HpackDecodingError mapped
// one to one), and Name its name without the SPDY_ prefix.
type QuicheError int

const (
	QuicheIndexVarintError       QuicheError = 11
	QuicheNameLengthVarintError  QuicheError = 12
	QuicheValueLengthVarintError QuicheError = 13
	QuicheNameTooLong            QuicheError = 14
	QuicheValueTooLong           QuicheError = 15
	QuicheNameHuffmanError       QuicheError = 16
	QuicheValueHuffmanError      QuicheError = 17
	QuicheInvalidIndex           QuicheError = 19
	QuicheInvalidNameIndex       QuicheError = 20
	QuicheSizeUpdateNotAllowed   QuicheError = 21
	QuicheSizeUpdateAboveSetting QuicheError = 23
	QuicheTruncatedBlock         QuicheError = 24
)

var quicheErrorNames = map[QuicheError]string{
	QuicheIndexVarintError:       "HPACK_INDEX_VARINT_ERROR",
	QuicheNameLengthVarintError:  "HPACK_NAME_LENGTH_VARINT_ERROR",
	QuicheValueLengthVarintError: "HPACK_VALUE_LENGTH_VARINT_ERROR",
	QuicheNameTooLong:            "HPACK_NAME_TOO_LONG",
	QuicheValueTooLong:           "HPACK_VALUE_TOO_LONG",
	QuicheNameHuffmanError:       "HPACK_NAME_HUFFMAN_ERROR",
	QuicheValueHuffmanError:      "HPACK_VALUE_HUFFMAN_ERROR",
	QuicheInvalidIndex:           "HPACK_INVALID_INDEX",
	QuicheInvalidNameIndex:       "HPACK_INVALID_NAME_INDEX",
	QuicheSizeUpdateNotAllowed:   "HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED",
	QuicheSizeUpdateAboveSetting: "HPACK_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING",
	QuicheTruncatedBlock:         "HPACK_TRUNCATED_BLOCK",
}

// Name returns the name of e in Chromium's GOAWAY debug data.
func (e QuicheError) Name() string { return quicheErrorNames[e] }

func (e QuicheError) Error() string { return fmt.Sprintf("hpack: %s", e.Name()) }

// [eidolon] SetQuicheErrors makes d decode as quiche's HpackDecoder, which
// Chromium uses, and fail with its errors, a QuicheError:
//   - an integer takes up to ten bytes after its prefix, and an index or a
//     table size above 2^32-1 is an error;
//   - the maximum string length limits the encoded length only, and every
//     Huffman string is decoded, even with the emit disabled;
//   - in a literal with an indexed name, the index is checked after the
//     value has been read;
//   - at most two dynamic table size updates start a header block, and
//     none follows a field.
func (d *Decoder) SetQuicheErrors(v bool) { d.quiche = v }

// errQuicheVarint is an integer that quiche's HpackVarintDecoder refuses.
var errQuicheVarint = errors.New("hpack: varint too long or too large")

// readVarIntQuiche reads an integer with an n-bit prefix as quiche's
// HpackVarintDecoder: at most ten bytes after the prefix, the tenth
// ending it with at most 1<<63 and no overflow. The errors are
// errNeedMore and errQuicheVarint.
func readVarIntQuiche(n byte, p []byte) (uint64, []byte, error) {
	if len(p) == 0 {
		return 0, p, errNeedMore
	}
	mask := uint64(1)<<n - 1
	i := uint64(p[0]) & mask
	if i < mask {
		return i, p[1:], nil
	}
	orig := p
	p = p[1:]
	for m := uint(0); ; m += 7 {
		if len(p) == 0 {
			return 0, orig, errNeedMore
		}
		b := uint64(p[0])
		p = p[1:]
		if m == 63 {
			if b&128 != 0 || b > 1 || i > math.MaxUint64-b<<63 {
				return 0, orig, errQuicheVarint
			}
			return i + b<<63, p, nil
		}
		i += (b & 127) << m
		if b&128 == 0 {
			return i, p, nil
		}
	}
}

// parseQuiche is parseHeaderFieldRepr with SetQuicheErrors, in the order
// of quiche's HpackEntryDecoder and HpackDecoderState.
func (d *Decoder) parseQuiche() error {
	b := d.buf[0]
	var n byte
	it := indexedFalse
	switch {
	case b&128 != 0: // indexed
		n = 7
	case b&192 == 64:
		n, it = 6, indexedTrue
	case b&224 == 32: // dynamic table size update
		n = 5
	case b&240 == 16:
		n, it = 4, indexedNever
	default:
		n = 4
	}
	v, buf, err := readVarIntQuiche(n, d.buf)
	if err == errNeedMore {
		return err
	}
	if err != nil || v > math.MaxUint32 {
		return QuicheIndexVarintError
	}
	switch {
	case n == 7:
		hf, ok := d.at(v)
		if !ok {
			return QuicheInvalidIndex
		}
		d.buf, d.sizeUpdates = buf, -1
		return d.callEmit(HeaderField{Name: hf.Name, Value: hf.Value})
	case n == 5:
		if d.sizeUpdates < 0 || d.sizeUpdates >= 2 {
			return QuicheSizeUpdateNotAllowed
		}
		if v > uint64(d.dynTab.allowedMaxSize) {
			return QuicheSizeUpdateAboveSetting
		}
		d.dynTab.setMaxSize(uint32(v))
		d.buf = buf
		d.sizeUpdates++
		return nil
	}
	var hf HeaderField
	if v == 0 {
		if hf.Name, buf, err = d.readStringQuiche(buf, true); err != nil {
			return err
		}
	}
	if hf.Value, buf, err = d.readStringQuiche(buf, false); err != nil {
		return err
	}
	if v > 0 {
		ihf, ok := d.at(v)
		if !ok {
			return QuicheInvalidNameIndex
		}
		hf.Name = ihf.Name
	}
	d.buf, d.sizeUpdates = buf, -1
	if it.indexed() {
		d.dynTab.add(hf)
	}
	hf.Sensitive = it.sensitive()
	return d.callEmit(hf)
}

// readStringQuiche reads and decodes a string of a name or a value, with
// the errors of quiche's HpackStringDecoder and HpackWholeEntryBuffer.
func (d *Decoder) readStringQuiche(p []byte, name bool) (string, []byte, error) {
	varint, tooLong, huffman := QuicheValueLengthVarintError, QuicheValueTooLong, QuicheValueHuffmanError
	if name {
		varint, tooLong, huffman = QuicheNameLengthVarintError, QuicheNameTooLong, QuicheNameHuffmanError
	}
	if len(p) == 0 {
		return "", p, errNeedMore
	}
	isHuff := p[0]&128 != 0
	n, p, err := readVarIntQuiche(7, p)
	if err == errNeedMore {
		return "", p, err
	}
	if err != nil {
		return "", p, varint
	}
	if d.maxStrLen != 0 && n > uint64(d.maxStrLen) {
		return "", p, tooLong
	}
	if uint64(len(p)) < n {
		return "", p, errNeedMore
	}
	s, rest := p[:n], p[n:]
	if !isHuff {
		return string(s), rest, nil
	}
	var buf bytes.Buffer
	if err := huffmanDecode(&buf, 0, s); err != nil {
		return "", rest, huffman
	}
	return buf.String(), rest, nil
}
