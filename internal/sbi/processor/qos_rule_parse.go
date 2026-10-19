package processor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/free5gc/nas/nasType"
)

// parseRequestedQoSRules parses a Requested-QoS-rules IE (TS 24.501 §9.11.4.13) from a
// UE PDU Session Modification Request.
//
// It replaces nasType.QoSRules.UnmarshalBinary, which has a bug: it ignores the per-rule
// "Length of QoS rule" field and unconditionally reads the QoS-rule-precedence and
// segregation/QFI octets after the packet-filter list. For a "delete existing QoS rule"
// operation those two octets are ABSENT (the rule length is 1 — just the rule-operation
// octet), so the upstream parser reads past the rule, consuming the next rule's bytes or
// hitting EOF; the whole IE then fails to parse. Here each rule is bounded to its declared
// length and precedence/QFI are read only when they are actually present.
func parseRequestedQoSRules(b []byte) (nasType.QoSRules, error) {
	rules := nasType.QoSRules{}
	buf := bytes.NewBuffer(b)

	for buf.Len() > 0 {
		rule := nasType.QoSRule{}
		if err := binary.Read(buf, binary.BigEndian, &rule.Identifier); err != nil {
			if err == io.EOF {
				break
			}
			return rules, err
		}

		var ruleLen uint16
		if err := binary.Read(buf, binary.BigEndian, &ruleLen); err != nil {
			return rules, err
		}

		// Bound this rule to its declared length. buf.Next returns min(ruleLen, remaining).
		content := buf.Next(int(ruleLen))
		if len(content) < int(ruleLen) {
			return rules, fmt.Errorf("QoS rule %d truncated: have %d, want %d bytes",
				rule.Identifier, len(content), ruleLen)
		}
		rc := bytes.NewBuffer(content)

		var header uint8
		if err := binary.Read(rc, binary.BigEndian, &header); err != nil {
			return rules, err
		}
		rule.Operation = nasType.QoSRuleOperationCode(header >> 5)
		rule.DQR = (header & (1 << 4)) != 0
		numPF := int(header & 0x0F)

		for i := 0; i < numPF; i++ {
			var pfHeader uint8
			if err := binary.Read(rc, binary.BigEndian, &pfHeader); err != nil {
				return rules, err
			}
			pf := nasType.PacketFilter{
				Identifier: pfHeader & 0x0F,
				Direction:  nasType.PacketFilterDirection((pfHeader & 0xF0) >> 4),
			}
			// A "...and delete packet filters" operation lists only filter identifiers;
			// every other operation carries a length + components for each filter.
			if rule.Operation != nasType.OperationCodeModifyExistingQoSRuleAndDeletePacketFilters {
				var pfLen uint8
				if err := binary.Read(rc, binary.BigEndian, &pfLen); err != nil {
					return rules, err
				}
				if err := pf.Components.UnmarshalBinary(rc.Next(int(pfLen))); err != nil {
					return rules, err
				}
			}
			rule.PacketFilterList = append(rule.PacketFilterList, pf)
		}

		// QoS rule precedence + segregation/QFI are present for create/modify operations
		// but not for a "delete existing QoS rule" (rule length == 1). Read them only when
		// the rule content still has both octets.
		if rc.Len() >= 2 {
			if err := binary.Read(rc, binary.BigEndian, &rule.Precedence); err != nil {
				return rules, err
			}
			var qfiByte uint8
			if err := binary.Read(rc, binary.BigEndian, &qfiByte); err != nil {
				return rules, err
			}
			rule.Segregation = (qfiByte >> 6) != 0
			rule.QFI = qfiByte & (1<<6 - 1)
		}

		rules = append(rules, rule)
	}

	return rules, nil
}
