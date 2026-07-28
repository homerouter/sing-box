//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdlib.h>
#include "singbox_ebpf.h"

static int singbox_ebpf_inbound_prepare(
	const char *cgroup_path,
	uint16_t listen_port,
	struct bpf2socks_bpf_runtime *runtime,
	int *saved_errno) {
	int result = bpf2socks_inbound_prepare(cgroup_path, listen_port, runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_inbound_attach(
	struct bpf2socks_bpf_runtime *runtime,
	int *saved_errno) {
	int result = bpf2socks_inbound_attach(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	bpfMapLookupElem = 1
	bpfMapUpdateElem = 2
)

type Backend struct {
	runtime    *C.struct_bpf2socks_bpf_runtime
	tokenMap   int
	cookieMap  int
	cgroupPath string
}

type mapElementAttr struct {
	MapFD uint32
	_     uint32
	Key   uint64
	Value uint64
	Flags uint64
}

func Prepare(cgroupPath string, listenPort uint16) (*Backend, error) {
	if cgroupPath == "" {
		var err error
		cgroupPath, err = DetectCgroup2Mount()
		if err != nil {
			return nil, err
		}
	}
	raiseMemlockLimit()
	runtimeState := (*C.struct_bpf2socks_bpf_runtime)(C.calloc(1, C.size_t(C.sizeof_struct_bpf2socks_bpf_runtime)))
	if runtimeState == nil {
		return nil, E.New("allocate eBPF runtime")
	}
	var cgroupPathCString *C.char
	if cgroupPath != "" {
		cgroupPathCString = C.CString(cgroupPath)
		defer C.free(unsafe.Pointer(cgroupPathCString))
	}
	var savedErrno C.int
	if C.singbox_ebpf_inbound_prepare(cgroupPathCString, C.uint16_t(listenPort), runtimeState, &savedErrno) != 0 {
		err := syscall.Errno(savedErrno)
		C.free(unsafe.Pointer(runtimeState))
		return nil, E.Cause(err, "prepare eBPF inbound")
	}
	return &Backend{
		runtime:    runtimeState,
		tokenMap:   int(runtimeState.token_map_fd),
		cookieMap:  int(runtimeState.bypass_socket_cookie_map_fd),
		cgroupPath: cgroupPath,
	}, nil
}

func raiseMemlockLimit() {
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit) != nil || limit.Cur >= limit.Max {
		return
	}
	limit.Cur = limit.Max
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit)
}

func (b *Backend) CgroupPath() string {
	if b == nil {
		return ""
	}
	return b.cgroupPath
}

func (b *Backend) Attach() error {
	if b == nil || b.runtime == nil {
		return osErrClosed
	}
	var savedErrno C.int
	if C.singbox_ebpf_inbound_attach(b.runtime, &savedErrno) != 0 {
		return E.Cause(syscall.Errno(savedErrno), "attach eBPF inbound")
	}
	return nil
}

func (b *Backend) Close() error {
	if b == nil || b.runtime == nil {
		return nil
	}
	C.bpf2socks_bpf_stop(b.runtime)
	C.free(unsafe.Pointer(b.runtime))
	b.runtime = nil
	b.tokenMap = -1
	b.cookieMap = -1
	return nil
}

func (b *Backend) ProtectFunc() control.Func {
	return func(network string, address string, rawConn syscall.RawConn) error {
		return control.Raw(rawConn, func(fd uintptr) error {
			cookie, err := socketCookie(fd)
			if err != nil {
				return E.Cause(err, "read socket cookie")
			}
			value := uint8(1)
			if err = updateMap(b.cookieMap, unsafe.Pointer(&cookie), unsafe.Pointer(&value)); err != nil {
				return E.Cause(err, "register eBPF bypass socket")
			}
			return nil
		})
	}
}

func (b *Backend) LookupOriginal(protocol uint8, token netip.AddrPort) (OriginalDestination, error) {
	key, err := makeTokenKey(protocol, token, netip.AddrPort{})
	if err != nil {
		return OriginalDestination{}, err
	}
	var original originalDestination
	err = lookupMap(b.tokenMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup original destination")
	}
	var address netip.Addr
	switch original.Family {
	case addressFamilyIPv4:
		address = netip.AddrFrom4([4]byte(original.Addr[:4]))
	case addressFamilyIPv6:
		address = netip.AddrFrom16(original.Addr)
	default:
		return OriginalDestination{}, E.New("invalid original destination family: ", original.Family)
	}
	return OriginalDestination{
		Destination:  netip.AddrPortFrom(address.Unmap(), original.Port),
		ConnectedUDP: original.Flags&1 != 0,
	}, nil
}

func lookupMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return mapOperation(bpfMapLookupElem, mapFD, key, value)
}

func updateMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return mapOperation(bpfMapUpdateElem, mapFD, key, value)
}

func mapOperation(command uintptr, mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	if mapFD < 0 {
		return osErrClosed
	}
	attribute := mapElementAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(uintptr(key)),
		Value: uint64(uintptr(value)),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, command, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if errno != 0 {
		return errno
	}
	return nil
}

func socketCookie(fd uintptr) (uint64, error) {
	var cookie uint64
	length := uint32(unsafe.Sizeof(cookie))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		fd,
		unix.SOL_SOCKET,
		unix.SO_COOKIE,
		uintptr(unsafe.Pointer(&cookie)),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return cookie, nil
}

var osErrClosed = syscall.EBADF
