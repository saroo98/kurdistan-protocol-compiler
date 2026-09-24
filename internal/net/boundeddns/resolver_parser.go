// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package boundeddns

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

var ErrResponse = errors.New("bounded DNS response rejected")
var ErrSizeLimit = errors.New("bounded DNS size limit")
var ErrNoData = errors.New("bounded DNS no data")
var errIrrelevant = errors.New("bounded DNS irrelevant response")

// Reused across all serial exchanges. No collection grows with wire records.
type workspace struct {
	query   [512]byte
	udp     [513]byte
	tcp     [65535]byte
	prefix  [2]byte
	results [16]netip.Addr
	names   [9]dnsmessage.Name
	count   int
}

func (w *workspace) clear() { *w = workspace{} }

func (w *workspace) buildQuery(kind dnsmessage.Type) ([]byte, uint16, error) {
	// A validated absolute name occupies Length+1 wire bytes. Preflight the
	// whole question because Builder itself is append-based, not a hard cap.
	n := int(w.names[0].Length)
	if n < 2 || n > 254 || w.names[0].Data[n-1] != '.' || 12+n+1+4 > 271 {
		return nil, 0, ErrResponse
	}
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, 0, ErrResponse
	}
	id := binary.BigEndian.Uint16(random[:])
	b := dnsmessage.NewBuilder(w.query[:0], dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, 0, ErrResponse
	}
	if err := b.Question(dnsmessage.Question{Name: w.names[0], Type: kind, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, ErrResponse
	}
	query, err := b.Finish()
	if err != nil {
		return nil, 0, ErrResponse
	}
	return query, id, nil
}

func sameName(a, b dnsmessage.Name) bool {
	if a.Length != b.Length {
		return false
	}
	for i := 0; i < int(a.Length); i++ {
		x, y := a.Data[i], b.Data[i]
		if x > 127 || y > 127 {
			return false
		}
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func responseStart(msg []byte, name dnsmessage.Name, kind dnsmessage.Type, id uint16) (dnsmessage.Header, dnsmessage.Parser, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return h, p, ErrResponse
	}
	if !h.Response || h.OpCode != 0 || h.ID != id {
		return h, p, errIrrelevant
	}
	q, err := p.Question()
	if err != nil {
		return h, p, ErrResponse
	}
	if !sameName(q.Name, name) || q.Type != kind || q.Class != dnsmessage.ClassINET {
		return h, p, errIrrelevant
	}
	if _, err = p.Question(); err != dnsmessage.ErrSectionDone {
		return h, p, ErrResponse
	}
	if h.RCode == dnsmessage.RCodeNameError {
		return h, p, ErrNoData
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return h, p, ErrResponse
	}
	return h, p, nil
}

func (w *workspace) acceptResponse(msg []byte, kind dnsmessage.Type, id uint16) (bool, error) {
	h, p, err := responseStart(msg, w.names[0], kind, id)
	if err != nil {
		return false, err
	}
	if h.Truncated {
		return true, nil
	}
	// Only fixed header fields are read here. Name decompression remains the
	// maintained Parser's job. Root owner + type/class/TTL/length needs 11 bytes.
	declared := int(binary.BigEndian.Uint16(msg[6:8])) + int(binary.BigEndian.Uint16(msg[8:10])) + int(binary.BigEndian.Uint16(msg[10:12]))
	if declared > (len(msg)-12)/11 {
		return false, ErrResponse
	}
	before := w.count
	for depth := 0; depth < len(w.names); depth++ {
		next, found, soa, ns, e := w.scan(p, kind, w.names[depth])
		if e != nil {
			return false, e
		}
		if !found {
			// Recursive/cache NODATA need not carry AA. A referral cannot
			// supply an empty family; an incomplete CNAME needs follow-up
			// unless a relevant terminal-zone SOA completes the result.
			if w.count == before && !soa && (depth > 0 || ns) {
				return false, ErrNoData
			}
			return false, nil
		}
		for i := 0; i <= depth; i++ {
			if sameName(next, w.names[i]) {
				return false, ErrResponse
			}
		}
		if depth+1 == len(w.names) {
			return false, ErrSizeLimit
		}
		w.names[depth+1] = next
	}
	return false, ErrResponse
}

// Every rescan checks every declared section. Only answer-section addresses
// for this chain endpoint can be retained; authority/additional glue cannot.
func (w *workspace) scan(p dnsmessage.Parser, kind dnsmessage.Type, current dnsmessage.Name) (next dnsmessage.Name, found, soa, ns bool, err error) {
	hasAddress := false
	for section := 0; section < 3; section++ {
		for {
			rh, e := resourceHeader(&p, section)
			if e == dnsmessage.ErrSectionDone {
				break
			}
			if e != nil {
				return next, false, false, false, ErrResponse
			}
			probe := p
			// Typed CNAME decoding cannot prove exact compressed RDATA
			// consumption. Skip on a copy first proves the declared extent.
			if skipResource(&probe, section) != nil {
				return next, false, false, false, ErrResponse
			}
			match := section == 0 && sameName(rh.Name, current)
			var address netip.Addr
			switch rh.Type {
			case dnsmessage.TypeA:
				if rh.Class != dnsmessage.ClassINET || rh.Length != 4 {
					return next, false, false, false, ErrResponse
				}
				a, e := p.AResource()
				if e != nil {
					return next, false, false, false, ErrResponse
				}
				address = netip.AddrFrom4(a.A)
			case dnsmessage.TypeAAAA:
				if rh.Class != dnsmessage.ClassINET || rh.Length != 16 {
					return next, false, false, false, ErrResponse
				}
				a, e := p.AAAAResource()
				if e != nil {
					return next, false, false, false, ErrResponse
				}
				address = netip.AddrFrom16(a.AAAA)
			case dnsmessage.TypeCNAME:
				if rh.Class != dnsmessage.ClassINET || rh.Length == 0 {
					return next, false, false, false, ErrResponse
				}
				c, e := p.CNAMEResource()
				if e != nil || !asciiName(c.CNAME) {
					return next, false, false, false, ErrResponse
				}
				if match {
					if found && !sameName(next, c.CNAME) {
						return next, false, false, false, ErrResponse
					}
					next = c.CNAME
					found = true
				}
			case dnsmessage.TypeSOA:
				if rh.Class != dnsmessage.ClassINET || rh.Length < 22 {
					return next, false, false, false, ErrResponse
				}
				if _, e := p.SOAResource(); e != nil {
					return next, false, false, false, ErrResponse
				}
				if section == 1 && enclosingZone(rh.Name, current) {
					soa = true
				}
			case dnsmessage.TypeNS:
				if rh.Class == dnsmessage.ClassINET {
					if rh.Length == 0 {
						return next, false, false, false, ErrResponse
					}
					if _, e := p.NSResource(); e != nil {
						return next, false, false, false, ErrResponse
					}
					if section == 1 {
						ns = true
					}
				} else if skipResource(&p, section) != nil {
					return next, false, false, false, ErrResponse
				}
			default:
				// No EDNS negotiation is emitted. An unsolicited OPT must
				// not turn an extended error or unknown version into NOERROR.
				if rh.Type == dnsmessage.TypeOPT && (rh.TTL&0x00ff0000 != 0 || rh.ExtendedRCode(dnsmessage.RCodeSuccess) != dnsmessage.RCodeSuccess) {
					return next, false, false, false, ErrResponse
				}
				if section == 0 && rh.Type == 39 {
					return next, false, false, false, ErrResponse
				} // DNAME is not an admitted chain form.
				if skipResource(&p, section) != nil {
					return next, false, false, false, ErrResponse
				}
			}
			if match && address.IsValid() {
				hasAddress = true
				if rh.Type == kind {
					if e = w.insert(address); e != nil {
						return next, false, false, false, e
					}
				}
			}
		}
	}
	if found && hasAddress {
		return next, false, false, false, ErrResponse
	}
	return next, found, soa, ns, nil
}

func enclosingZone(zone, terminal dnsmessage.Name) bool {
	if zone.Length == 1 && zone.Data[0] == '.' {
		return true
	}
	offset := int(terminal.Length) - int(zone.Length)
	if offset < 0 || (offset > 0 && terminal.Data[offset-1] != '.') {
		return false
	}
	var suffix dnsmessage.Name
	copy(suffix.Data[:], terminal.Data[offset:terminal.Length])
	suffix.Length = zone.Length
	return sameName(zone, suffix)
}

func asciiName(n dnsmessage.Name) bool {
	if n.Length < 2 {
		return false
	}
	for _, c := range n.Data[:n.Length] {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func resourceHeader(p *dnsmessage.Parser, section int) (dnsmessage.ResourceHeader, error) {
	switch section {
	case 0:
		return p.AnswerHeader()
	case 1:
		return p.AuthorityHeader()
	default:
		return p.AdditionalHeader()
	}
}

func skipResource(p *dnsmessage.Parser, section int) error {
	switch section {
	case 0:
		return p.SkipAnswer()
	case 1:
		return p.SkipAuthority()
	default:
		return p.SkipAdditional()
	}
}

func (w *workspace) insert(a netip.Addr) error {
	for i := 0; i < w.count; i++ {
		if w.results[i] == a {
			return nil
		}
	}
	if w.count == len(w.results) {
		return ErrSizeLimit
	}
	w.results[w.count] = a
	w.count++
	return nil
}
