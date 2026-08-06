package clashapi

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type ebpfDiagnosticsProvider interface {
	EBPFDiagnostics() (map[string]map[string]uint64, error)
}

type ebpfInboundDiagnostics struct {
	Tag         string                       `json:"tag"`
	Diagnostics map[string]map[string]uint64 `json:"diagnostics"`
	Error       string                       `json:"error,omitempty"`
}

func (s *Server) setupEBPFAPI(router chi.Router) {
	router.Get("/ebpf", func(writer http.ResponseWriter, request *http.Request) {
		inboundManager := service.FromContext[adapter.InboundManager](s.ctx)
		render.JSON(writer, request, render.M{"inbounds": collectEBPFDiagnostics(inboundManager.Inbounds())})
	})
}

func collectEBPFDiagnostics(inbounds []adapter.Inbound) []ebpfInboundDiagnostics {
	response := make([]ebpfInboundDiagnostics, 0)
	for _, inbound := range inbounds {
		provider, loaded := inbound.(ebpfDiagnosticsProvider)
		if !loaded {
			continue
		}
		diagnostics, err := provider.EBPFDiagnostics()
		entry := ebpfInboundDiagnostics{
			Tag:         inbound.Tag(),
			Diagnostics: diagnostics,
		}
		if err != nil {
			entry.Error = err.Error()
		}
		response = append(response, entry)
	}
	return response
}
