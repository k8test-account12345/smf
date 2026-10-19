package processor

import (
	"testing"

	"github.com/free5gc/nas/nasType"
)

// A "delete existing QoS rule" (TS 24.501 §9.11.4.13): identifier=1, length=1, and the
// single content octet = rule operation (010 = delete) << 5 = 0x40. No packet filters,
// no precedence, no QFI.
var deleteRuleIE = []byte{0x01, 0x00, 0x01, 0x40}

// A "create new QoS rule": identifier=2, length=6, content = [op create(001)<<5 | numPF 1
// = 0x21][pf: dir bidir(3)<<4 | id 1 = 0x31, len 1, match-all component 0x01][precedence
// 0xFF][segregation 0 | QFI 9 = 0x09].
var createRuleIE = []byte{0x02, 0x00, 0x06, 0x21, 0x31, 0x01, 0x01, 0xFF, 0x09}

func TestParseRequestedQoSRules_DeleteRule(t *testing.T) {
	// The upstream parser reads precedence/QFI unconditionally and overruns on a delete
	// rule — this is the bug the local parser works around.
	var upstream nasType.QoSRules
	if err := upstream.UnmarshalBinary(deleteRuleIE); err == nil {
		t.Log("note: upstream nasType.QoSRules.UnmarshalBinary accepted the delete-rule (bug not reproduced here)")
	} else {
		t.Logf("confirmed upstream bug: %v", err)
	}

	rules, err := parseRequestedQoSRules(deleteRuleIE)
	if err != nil {
		t.Fatalf("parseRequestedQoSRules(delete) error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].Operation != nasType.OperationCodeDeleteExistingQoSRule {
		t.Errorf("operation = %d, want delete (%d)", rules[0].Operation, nasType.OperationCodeDeleteExistingQoSRule)
	}
	if len(rules[0].PacketFilterList) != 0 {
		t.Errorf("delete-rule packet filters = %d, want 0", len(rules[0].PacketFilterList))
	}
}

func TestParseRequestedQoSRules_CreateRule(t *testing.T) {
	rules, err := parseRequestedQoSRules(createRuleIE)
	if err != nil {
		t.Fatalf("parseRequestedQoSRules(create) error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r := rules[0]
	if r.Operation != nasType.OperationCodeCreateNewQoSRule {
		t.Errorf("operation = %d, want create (%d)", r.Operation, nasType.OperationCodeCreateNewQoSRule)
	}
	if r.QFI != 9 {
		t.Errorf("QFI = %d, want 9", r.QFI)
	}
	if r.Precedence != 0xFF {
		t.Errorf("precedence = %d, want 255", r.Precedence)
	}
	if len(r.PacketFilterList) != 1 {
		t.Errorf("packet filters = %d, want 1", len(r.PacketFilterList))
	}
}

// The exact shape the upstream parser desyncs on: a delete-rule whose (absent) precedence/
// QFI it wrongly reads from the following create-rule.
func TestParseRequestedQoSRules_DeleteThenCreate(t *testing.T) {
	mixed := append(append([]byte{}, deleteRuleIE...), createRuleIE...)
	rules, err := parseRequestedQoSRules(mixed)
	if err != nil {
		t.Fatalf("parseRequestedQoSRules(mixed) error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Operation != nasType.OperationCodeDeleteExistingQoSRule {
		t.Errorf("rule[0] op = %d, want delete", rules[0].Operation)
	}
	if rules[1].Operation != nasType.OperationCodeCreateNewQoSRule || rules[1].QFI != 9 {
		t.Errorf("rule[1] op/QFI = %d/%d, want create/9", rules[1].Operation, rules[1].QFI)
	}
}
