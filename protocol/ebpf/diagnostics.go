//go:build with_ebpf && (linux || android)

package ebpf

import (
	E "github.com/sagernet/sing/common/exceptions"
)

func (i *Inbound) EBPFDiagnostics() (map[string]map[string]uint64, error) {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	diagnostics := make(map[string]map[string]uint64, 2)
	var diagnosticsErr error
	if backend := i.cgroupBackendInstance(); backend != nil {
		counters, err := backend.DiagnosticCounters()
		if err != nil {
			diagnosticsErr = E.Append(diagnosticsErr, err, func(err error) error {
				return E.Cause(err, "read local cgroup diagnostics")
			})
		} else {
			diagnostics["local"] = counters
		}
	}
	if i.sharedNetwork != nil {
		if backend := i.sharedNetwork.sharedBackendInstance(); backend != nil {
			counters, err := backend.DiagnosticCounters()
			if err != nil {
				diagnosticsErr = E.Append(diagnosticsErr, err, func(err error) error {
					return E.Cause(err, "read shared-network diagnostics")
				})
			} else {
				diagnostics["shared_network"] = counters
			}
		}
	}
	return diagnostics, diagnosticsErr
}
