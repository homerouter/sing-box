//go:build with_ebpf && linux && cgo && ebpf_integration

package ebpf

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const bpfProgramTestRun = 10

type programTestRunAttr struct {
	ProgramFD      uint32
	ReturnValue    uint32
	DataSizeIn     uint32
	DataSizeOut    uint32
	DataIn         uint64
	DataOut        uint64
	Repeat         uint32
	Duration       uint32
	ContextSizeIn  uint32
	ContextSizeOut uint32
	ContextIn      uint64
	ContextOut     uint64
	Flags          uint32
	CPU            uint32
}

func TestSharedNetworkIPv6ExtensionHeadersIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test shared-network IPv6 extension headers")
	backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{
		ListenerPort: 65530,
		EnableTCP:    true,
		EnableUDP:    true,
		HijackDNS:    true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		MapCapacity:  SharedNetworkMapCapacity,
		UDPTimeout:   5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}

	for _, extensionHeaderCount := range []int{5, 8} {
		t.Run(strconv.Itoa(extensionHeaderCount)+"_headers", func(t *testing.T) {
			testSharedNetworkIPv6ExtensionPacket(t, backend, extensionHeaderCount)
		})
	}
}

func testSharedNetworkIPv6ExtensionPacket(t *testing.T, backend *SharedNetworkBackend, extensionHeaderCount int) {
	t.Helper()
	packet := ipv6ExtensionHeaderTestPacket(extensionHeaderCount)
	output := make([]byte, len(packet))
	attribute := programTestRunAttr{
		ProgramFD:   uint32(backend.IngressProgramFD()),
		DataSizeIn:  uint32(len(packet)),
		DataSizeOut: uint32(len(output)),
		DataIn:      uint64(uintptr(unsafe.Pointer(&packet[0]))),
		DataOut:     uint64(uintptr(unsafe.Pointer(&output[0]))),
		Repeat:      1,
	}
	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfProgramTestRun,
		uintptr(unsafe.Pointer(&attribute)),
		unsafe.Sizeof(attribute),
	)
	runtime.KeepAlive(packet)
	runtime.KeepAlive(output)
	if errors.Is(errno, unix.EOPNOTSUPP) || errno == linuxErrnoNotSupported {
		t.Skip("kernel does not support TC BPF_PROG_TEST_RUN")
	}
	if errno != 0 {
		t.Fatal(errno)
	}
	if attribute.ReturnValue != 0 {
		t.Fatalf("unexpected TC action: %d", attribute.ReturnValue)
	}
	if attribute.DataSizeOut != uint32(len(packet)) {
		t.Fatalf("unexpected output length: %d", attribute.DataSizeOut)
	}
	originalDestination := packet[38:54]
	rewrittenDestination := output[38:54]
	if string(rewrittenDestination) == string(originalDestination) {
		t.Fatal("IPv6 destination was not rewritten after extension-header parsing")
	}
	redirectPrefix := netip.MustParseAddr("fd53:696e:672d:626f::").As16()
	if string(rewrittenDestination[:8]) != string(redirectPrefix[:8]) {
		t.Fatalf("unexpected rewritten IPv6 destination: %x", rewrittenDestination)
	}
}

func ipv6ExtensionHeaderTestPacket(extensionHeaderCount int) []byte {
	packet := make([]byte, 14+40+extensionHeaderCount*8+20)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	ipv6 := packet[14:54]
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(extensionHeaderCount*8+20))
	extensionTypes := [...]byte{0, 60, 43, 60, 51, 60, 43, 60}
	ipv6[6] = extensionTypes[0]
	ipv6[7] = 64
	source := netip.MustParseAddr("2001:db8::2").As16()
	destination := netip.MustParseAddr("2001:4860:4860::8888").As16()
	copy(ipv6[8:24], source[:])
	copy(ipv6[24:40], destination[:])
	for index := 0; index < extensionHeaderCount; index++ {
		extension := packet[54+index*8 : 54+(index+1)*8]
		if index+1 == extensionHeaderCount {
			extension[0] = 6
		} else {
			extension[0] = extensionTypes[index+1]
		}
		extension[1] = 0
	}
	tcp := packet[54+extensionHeaderCount*8:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint16(tcp[12:14], 0x5002)
	return packet
}
