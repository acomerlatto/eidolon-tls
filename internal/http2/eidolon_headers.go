// Fragmenting of header blocks as Chromium (patch 0032).

package http2

// chromiumMaxControlFrame is quiche's kHttp2MaxControlFrameSendSize, the
// largest HEADERS or CONTINUATION frame Chromium sends, its 9-byte header
// included, whatever the MAX_FRAME_SIZE of the server.
const chromiumMaxControlFrame = 16383
