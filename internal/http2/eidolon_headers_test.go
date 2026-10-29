// Fragmenting of header blocks into HEADERS and CONTINUATION (patches 0031
// and 0032).

package http2

import (
	"bufio"
	"bytes"
	"io"
	"slices"
	"testing"
)

// writtenFragments writes a header block of n bytes with writeHeaders and
// returns the payload sizes of the frames written, which carry the block
// whole.
func writtenFragments(t *testing.T, tr *Transport, maxFrameSize, n int, prio PriorityParam) []int {
	t.Helper()
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	cc := &ClientConn{t: tr, bw: bw, fr: NewFramer(bw, nil)}
	block := make([]byte, n)
	for i := range block {
		block[i] = byte(i)
	}
	if err := cc.writeHeaders(1, true, maxFrameSize, block, prio); err != nil {
		t.Fatal(err)
	}
	fr := NewFramer(io.Discard, &buf)
	fr.SetMaxReadFrameSize(1 << 24)
	var sizes []int
	var got []byte
	for {
		f, err := fr.ReadFrame()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, int(f.Header().Length))
		switch f := f.(type) {
		case *HeadersFrame:
			if f.Priority != prio {
				t.Errorf("priority %+v, want %+v", f.Priority, prio)
			}
			got = append(got, f.HeaderBlockFragment()...)
		case *ContinuationFrame:
			got = append(got, f.HeaderBlockFragment()...)
		}
	}
	if !bytes.Equal(got, block) {
		t.Error("the header block is not carried whole")
	}
	return sizes
}

// The priority fields of HEADERS count in its payload: with them, the
// first fragment leaves 5 bytes to stay within the MAX_FRAME_SIZE of the
// server.
func TestWriteHeadersFrameSize(t *testing.T) {
	prio := PriorityParam{StreamDep: 3, Exclusive: true, Weight: 182}
	for _, tt := range []struct {
		name string
		max  int
		n    int
		prio PriorityParam
		want []int
	}{
		{"priority", 16384, 40000, prio, []int{16384, 16384, 7237}},
		{"no priority", 16384, 40000, PriorityParam{}, []int{16384, 16384, 7232}},
		{"priority, larger frames", 20000, 40000, prio, []int{20000, 20000, 5}},
		{"priority, one frame", 16384, 16379, prio, []int{16384}},
		{"priority, just over", 16384, 16380, prio, []int{16384, 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := writtenFragments(t, &Transport{}, tt.max, tt.n, tt.prio)
			if !slices.Equal(got, tt.want) {
				t.Errorf("frames of %v bytes, want %v", got, tt.want)
			}
		})
	}
}

// With ChromiumHeaderFraming, the frames are of at most 16383 bytes with
// their header, as quiche's kHttp2MaxControlFrameSendSize, whatever the
// MAX_FRAME_SIZE of the server; the priority fields count in them too.
func TestChromiumHeaderFraming(t *testing.T) {
	prio := PriorityParam{StreamDep: 3, Exclusive: true, Weight: 182}
	for _, tt := range []struct {
		name string
		max  int
		n    int
		prio PriorityParam
		want []int
	}{
		{"priority", 16384, 40000, prio, []int{16374, 16374, 7257}},
		{"no priority", 16384, 40000, PriorityParam{}, []int{16374, 16374, 7252}},
		{"priority, larger frames", 1 << 20, 40000, prio, []int{16374, 16374, 7257}},
		{"priority, one frame", 16384, 16369, prio, []int{16374}},
		{"priority, just over", 16384, 16370, prio, []int{16374, 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := writtenFragments(t, &Transport{ChromiumHeaderFraming: true}, tt.max, tt.n, tt.prio)
			if !slices.Equal(got, tt.want) {
				t.Errorf("frames of %v bytes, want %v", got, tt.want)
			}
		})
	}
}
