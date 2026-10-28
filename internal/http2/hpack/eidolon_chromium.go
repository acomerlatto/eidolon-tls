package hpack

// SetChromiumPolicy makes e encode as quiche's HpackEncoder, the one of
// Chromium (DefaultPolicy): among the pseudo-headers only :authority is
// indexed, the others going as literals without indexing; any other field
// is indexed, even one larger than the table, which then empties it (RFC
// 7541 section 4.4); and a name of the static table refers to its first
// entry, as :path to 4, not 5. A field marked Sensitive is still never
// indexed.
func (e *Encoder) SetChromiumPolicy(on bool) {
	e.chromium = on
}

// chromiumIndex reports whether e indexes f under the Chromium policy.
func chromiumIndex(f HeaderField) bool {
	if f.Sensitive {
		return false
	}
	return !f.IsPseudo() || f.Name == ":authority"
}

// firstStaticName returns the first index of the static table with the
// name at index i, for i in the static table.
func firstStaticName(i uint64) uint64 {
	for i > 1 && staticTable.ents[i-2].Name == staticTable.ents[i-1].Name {
		i--
	}
	return i
}

// ApplyHeaderTableSizeSetting adopts the SETTINGS_HEADER_TABLE_SIZE the
// peer announced, as quiche's HpackEncoder: nothing changes when it is the
// size in force; otherwise the table takes it, at any size, and the next
// field starts with a Dynamic Table Size Update to it. If a setting since
// the last update lowered the size below that, an update to the smallest
// size it lowered to comes first.
func (e *Encoder) ApplyHeaderTableSizeSetting(v uint32) {
	if v == e.dynTab.maxSize {
		return
	}
	if v < e.dynTab.maxSize {
		e.minSize = min(e.minSize, v)
	}
	e.dynTab.setMaxSize(v)
	e.tableSizeUpdate = true
}
