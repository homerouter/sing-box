//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
)

func readDiagnosticCounters(mapFD int, names []string) (map[string]uint64, error) {
	counters := make(map[string]uint64, len(names))
	for index, name := range names {
		key := uint32(index)
		var value uint64
		if err := lookupMap(mapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			return nil, E.Cause(err, "read eBPF diagnostic counter ", name)
		}
		counters[name] = value
	}
	return counters, nil
}

func (b *CgroupBackend) DiagnosticCounters() (map[string]uint64, error) {
	if b == nil {
		return nil, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return nil, err
	}
	return readDiagnosticCounters(int(b.runtime.stats_map_fd), cgroupDiagnosticCounterNames)
}

func (b *SharedNetworkBackend) DiagnosticCounters() (map[string]uint64, error) {
	if b == nil {
		return nil, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if err := b.requireUsableLocked(); err != nil {
		return nil, err
	}
	return readDiagnosticCounters(int(b.runtime.stats_map_fd), sharedNetworkDiagnosticCounterNames)
}
