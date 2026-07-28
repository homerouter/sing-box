package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestTokenABI(t *testing.T) {
	if size := unsafe.Sizeof(tokenKey{}); size != 40 {
		t.Fatalf("unexpected token key size: %d", size)
	}
	if size := unsafe.Sizeof(originalDestination{}); size != 24 {
		t.Fatalf("unexpected original destination size: %d", size)
	}

	key, err := makeTokenKey(
		ProtocolUDP,
		netip.MustParseAddrPort("[::ffff:127.2.3.4]:65532"),
		netip.MustParseAddrPort("[::ffff:127.0.0.1]:12345"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if key.Family != addressFamilyIPv4 || key.TokenPort != 65532 || key.ClientPort != 12345 {
		t.Fatalf("unexpected token key header: %+v", key)
	}
	if [4]byte(key.TokenAddr[:4]) != [4]byte{127, 2, 3, 4} {
		t.Fatalf("unexpected token address: %v", key.TokenAddr)
	}
	if [4]byte(key.ClientAddr[:4]) != [4]byte{127, 0, 0, 1} {
		t.Fatalf("unexpected client address: %v", key.ClientAddr)
	}
}
