package clashapi

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type testEBPFDiagnosticsInbound struct {
	adapter.Inbound
	tag         string
	diagnostics map[string]map[string]uint64
	err         error
}

func (i *testEBPFDiagnosticsInbound) Tag() string { return i.tag }

func (i *testEBPFDiagnosticsInbound) EBPFDiagnostics() (map[string]map[string]uint64, error) {
	return i.diagnostics, i.err
}

func TestCollectEBPFDiagnostics(t *testing.T) {
	expected := map[string]map[string]uint64{"local": {"redirect_reservation_failed": 2}}
	result := collectEBPFDiagnostics([]adapter.Inbound{
		&testEBPFDiagnosticsInbound{tag: "ebpf-in", diagnostics: expected},
		&testEBPFDiagnosticsInbound{tag: "ebpf-error", err: errors.New("read failed")},
	})
	if len(result) != 2 {
		t.Fatalf("unexpected diagnostics count: %d", len(result))
	}
	if result[0].Tag != "ebpf-in" || result[0].Diagnostics["local"]["redirect_reservation_failed"] != 2 {
		t.Fatalf("unexpected diagnostics: %+v", result[0])
	}
	if result[1].Tag != "ebpf-error" || result[1].Error != "read failed" {
		t.Fatalf("unexpected diagnostic error: %+v", result[1])
	}
}
