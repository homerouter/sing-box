package ebpf

var cgroupDiagnosticCounterNames = []string{
	"redirect_reservation_failed",
	"connected_udp_state_failed",
	"udp_flow_update_failed",
	"udp_peer_update_failed",
}

var sharedNetworkDiagnosticCounterNames = []string{
	"token_reservation_failed",
	"bypass_cache_update_failed",
	"packet_rewrite_failed",
	"scratch_lookup_failed",
}
