// Package dns implements a minimal, allocation-light DNS wire-format decoder.
//
// It is deliberately tolerant: DNS responses captured by the eBPF program may be
// truncated (we only copy the first ~512 bytes in-kernel), so Decode returns
// whatever it successfully parsed along with an error describing where it
// stopped. Callers should use the returned message if QName is populated, even
// when err != nil.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Resource record types we care about.
const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypePTR   = 12
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33
)

// ErrTruncated is returned when the message ends before parsing completes.
var ErrTruncated = errors.New("dns: message truncated")

// Message is the decoded view of a DNS packet that this monitor needs.
type Message struct {
	ID      uint16
	QR      bool // true for responses
	Opcode  uint8
	Rcode   uint8
	QDCount uint16
	ANCount uint16
	QName   string
	QType   uint16
	Answers []net.IP // A / AAAA records
	CNAMEs  []string
}

// readName decodes a (possibly compressed) DNS name starting at off. It returns
// the decoded name and the offset immediately after the name in the original
// stream (which, for a compressed name, is after the 2-byte pointer).
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	jumps := 0
	i := off

	for {
		if i >= len(msg) {
			return "", 0, ErrTruncated
		}
		b := msg[i]

		switch {
		case b == 0: // end of name
			i++
			if next == -1 {
				next = i
			}
			name := strings.Join(labels, ".")
			if name == "" {
				name = "."
			}
			return name, next, nil

		case b&0xC0 == 0xC0: // compression pointer
			if i+1 >= len(msg) {
				return "", 0, ErrTruncated
			}
			ptr := int(binary.BigEndian.Uint16(msg[i:i+2]) & 0x3FFF)
			if next == -1 {
				next = i + 2
			}
			if jumps++; jumps > 64 {
				return "", 0, errors.New("dns: too many compression jumps")
			}
			if ptr >= len(msg) {
				return "", 0, ErrTruncated
			}
			i = ptr

		default: // ordinary label
			l := int(b)
			i++
			if i+l > len(msg) {
				return "", 0, ErrTruncated
			}
			labels = append(labels, string(msg[i:i+l]))
			i += l
			if len(labels) > 128 {
				return "", 0, errors.New("dns: too many labels")
			}
		}
	}
}

// Decode parses a raw DNS message (starting at the 12-byte header).
func Decode(msg []byte) (*Message, error) {
	if len(msg) < 12 {
		return nil, ErrTruncated
	}

	m := &Message{
		ID:      binary.BigEndian.Uint16(msg[0:2]),
		QDCount: binary.BigEndian.Uint16(msg[4:6]),
		ANCount: binary.BigEndian.Uint16(msg[6:8]),
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	m.QR = flags&0x8000 != 0
	m.Opcode = uint8((flags >> 11) & 0x0F)
	m.Rcode = uint8(flags & 0x0F)

	off := 12

	// Question section.
	for q := 0; q < int(m.QDCount); q++ {
		name, nxt, err := readName(msg, off)
		if err != nil {
			return m, err
		}
		off = nxt
		if off+4 > len(msg) {
			return m, ErrTruncated
		}
		qtype := binary.BigEndian.Uint16(msg[off : off+2])
		off += 4 // QTYPE + QCLASS
		if q == 0 {
			m.QName = name
			m.QType = qtype
		}
	}

	// Answer section.
	for a := 0; a < int(m.ANCount); a++ {
		_, nxt, err := readName(msg, off) // owner name
		if err != nil {
			return m, err
		}
		off = nxt
		if off+10 > len(msg) {
			return m, ErrTruncated
		}
		atype := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return m, ErrTruncated
		}

		switch atype {
		case TypeA:
			if rdlen == 4 {
				m.Answers = append(m.Answers, net.IP(append([]byte(nil), msg[off:off+4]...)))
			}
		case TypeAAAA:
			if rdlen == 16 {
				m.Answers = append(m.Answers, net.IP(append([]byte(nil), msg[off:off+16]...)))
			}
		case TypeCNAME:
			if cname, _, err := readName(msg, off); err == nil {
				m.CNAMEs = append(m.CNAMEs, cname)
			}
		}
		off += rdlen
	}

	return m, nil
}

// TypeString maps a query type to a short label suitable for metrics.
func TypeString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// RcodeString maps a response code to a short label suitable for metrics.
func RcodeString(r uint8) string {
	switch r {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", r)
	}
}
