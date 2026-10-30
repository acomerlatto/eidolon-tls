package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// dohHandler answers the DoH queries of the browser (RFC 8484): A queries
// of the lab names with 127.0.0.1, an HTTPS query of DoHSiteHost on port
// with a record for h2 and, when echList is not empty, an ech parameter
// with it; NOERROR without records for the other queries of the lab names,
// and NXDOMAIN for the rest.
func dohHandler(port int, echList []byte) http.Handler {
	site := fmt.Sprintf("_%d._https.%s.", port, hostDoHSite)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			q, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		case http.MethodPost:
			q, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var m dnsmessage.Message
		if err == nil {
			err = m.Unpack(q)
		}
		if err != nil || len(m.Questions) != 1 {
			http.Error(w, "query", http.StatusBadRequest)
			return
		}
		question := m.Questions[0]
		name := strings.ToLower(question.Name.String())
		log.Printf("DoH %s %v %s", r.Method, question.Type, name)
		m.Header.Response, m.Header.RecursionAvailable = true, true
		m.Answers, m.Authorities, m.Additionals = nil, nil, nil
		hdr := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
		switch {
		case question.Type == dnsmessage.TypeA && strings.HasSuffix(name, ".lab.test."):
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
		case question.Type == dnsmessage.TypeHTTPS && name == site:
			hdr.Type = dnsmessage.TypeHTTPS
			// Priority 1, target ".", alpn=h2.
			data := []byte{0, 1, 0, 0, 1, 0, 3, 2, 'h', '2'}
			if len(echList) > 0 {
				// With the port prefix, the target "." is the owner
				// name, not the host of the A records: Chrome uses the
				// ECHConfigList only with the host as target.
				target := []byte{0, 1}
				for label := range strings.SplitSeq(hostDoHSite, ".") {
					target = append(target, byte(len(label)))
					target = append(target, label...)
				}
				data = append(append(target, 0), data[3:]...)
				data = append(data, 0, 5, byte(len(echList)>>8), byte(len(echList)))
				data = append(data, echList...)
			}
			m.Answers = append(m.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.UnknownResource{Type: dnsmessage.TypeHTTPS, Data: data}})
		case strings.HasSuffix(name, ".lab.test."):
		default:
			m.Header.RCode = dnsmessage.RCodeNameError
		}
		resp, err := m.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(resp)
	})
}
