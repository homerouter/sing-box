//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	"net/netip"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

type Backend struct{}

func Prepare(string, uint16) (*Backend, error) {
	return nil, E.New("eBPF inbound requires cgo")
}

func (b *Backend) Attach() error {
	return E.New("eBPF inbound requires cgo")
}

func (b *Backend) Close() error {
	return nil
}

func (b *Backend) CgroupPath() string {
	return ""
}

func (b *Backend) ProtectFunc() control.Func {
	return nil
}

func (b *Backend) LookupOriginal(uint8, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, E.New("eBPF inbound requires cgo")
}
