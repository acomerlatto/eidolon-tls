// HPACK of Chromium on the connection (patch 0022).

package http2

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/http"
	"testing"
)

// With ChromiumHPACK the first block has a size update only when the
// server announces a size other than 4096, at any size, and :path is never
// indexed; without it, any HEADER_TABLE_SIZE announced brings an update,
// at most 4096, and :path is indexed.
func TestChromiumHPACK(t *testing.T) {
	path := []byte{0x04, 0x02, '/', 'a'} // :path /a without indexing
	for _, tt := range []struct {
		name     string
		chromium bool
		table    uint32 // HEADER_TABLE_SIZE of the server, 0 for none
		update   string // hex of the size update starting the first block
		literal  bool   // :path /a literal in the second block
	}{
		{"chromium 4096", true, 4096, "", true},
		{"chromium 65536", true, 65536, "3fe1ff03", true},
		{"chromium none", true, 0, "", true},
		{"default 4096", false, 4096, "3fe11f", false},
		{"default 65536", false, 65536, "3fe11f", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { client.Close() })
			var o wireOptions
			if tt.table != 0 {
				o.settings = []Setting{{ID: SettingHeaderTableSize, Val: tt.table}}
			}
			seen := wireServer(server, o)
			cc, err := (&Transport{ChromiumHPACK: tt.chromium}).newClientConn(client, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := cc.Ping(t.Context()); err != nil { // the server SETTINGS are in force
				t.Fatal(err)
			}
			for range 2 {
				req, _ := http.NewRequest(http.MethodGet, "https://example.com/a", nil)
				resp, err := cc.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
			}
			var blocks [][]byte
			for f := range seen {
				if f.typ == FrameHeaders {
					if blocks = append(blocks, f.block); len(blocks) == 2 {
						break
					}
				}
			}
			update, _ := hex.DecodeString(tt.update)
			if !bytes.HasPrefix(blocks[0], update) || blocks[0][len(update)]&0xe0 == 0x20 {
				t.Errorf("first block %x, want the size update %q only", blocks[0], tt.update)
			}
			if got := bytes.Contains(blocks[1], path); got != tt.literal {
				t.Errorf("second block %x: :path literal %v, want %v", blocks[1], got, tt.literal)
			}
		})
	}
}
