// Package dns queries the HTTPS records (RFC 9460) of origins and reads them
// as Chrome 156 does (net/dns): the query is Chrome's DnsQuery and the
// answer is read as its DnsResponse and ExtractHttpsResults read it.
package dns

import (
	"errors"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// maxUDPPayload is the UDP payload size of the OPT record of Chrome's
	// queries (kMaxUdpPayloadSize).
	maxUDPPayload = 4096
	// padBlock is the block the padding of a DoH query fills (RFC 8467,
	// BLOCK_LENGTH_128).
	padBlock = 128
	// optFixed is the size of an OPT record without options, and
	// optHeader the size of an option header (code and length).
	optFixed  = 11
	optHeader = 4
)

// Query returns the query for qtype of name, a host name with no trailing
// dot, as Chrome's DnsQuery writes it: the ID, only RD among the flags and
// one question. With pad, as for DoH, an OPT record (UDP payload 4096)
// follows, whose padding option (RFC 7830) makes the query a multiple of
// 128 bytes (RFC 8467). Without pad there is no OPT record.
func Query(id uint16, name string, qtype dnsmessage.Type, pad bool) ([]byte, error) {
	if name == "" || strings.HasSuffix(name, ".") {
		return nil, errors.New("dns: invalid name " + name)
	}
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if !pad {
		return b.Finish()
	}
	// The size without the OPT record: the header and the question.
	unpadded := 12 + len(n.String()) + 1 + 4 + optFixed
	padding := optHeader + (padBlock-(optHeader+unpadded)%padBlock)%padBlock
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	opt := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: maxUDPPayload}
	err = b.OPTResource(opt, dnsmessage.OPTResource{Options: []dnsmessage.Option{
		{Code: 12, Data: make([]byte, padding-optHeader)},
	}})
	if err != nil {
		return nil, err
	}
	return b.Finish()
}
