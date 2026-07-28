package include

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestEBPFInboundMinimalOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{"type":"ebpf","tag":"ebpf-in"}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	if inboundOptions.Type != "ebpf" || inboundOptions.Tag != "ebpf-in" {
		t.Fatalf("unexpected inbound header: %+v", inboundOptions)
	}
	if _, loaded := inboundOptions.Options.(*option.EBPFInboundOptions); !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
}
