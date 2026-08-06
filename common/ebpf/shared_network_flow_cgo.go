//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"errors"
	"net/netip"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

var sharedFlowDeleteBatchSupport mapBatchSupport

func (b *SharedNetworkBackend) LookupOriginal(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (OriginalDestination, error) {
	original, _, err := b.lookupFlow(protocol, client, tokenDestination, false)
	return original, err
}

func (b *SharedNetworkBackend) LookupFlow(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	return b.lookupFlow(protocol, client, tokenDestination, true)
}

func (b *SharedNetworkBackend) lookupFlow(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
	retain bool,
) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	if b == nil {
		return OriginalDestination{}, nil, errBackendClosed
	}
	key, err := makeSharedNetworkListenerKey(protocol, client, tokenDestination)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, nil, errBackendClosed
	}
	if retain {
		b.flowAccess.Lock()
		defer b.flowAccess.Unlock()
	}
	var value sharedNetworkOriginalValue
	if err = lookupMap(
		int(b.runtime.listener_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
	); err != nil {
		return OriginalDestination{}, nil, E.Cause(err, "lookup shared-network original destination")
	}
	address, err := sharedNetworkOriginalAddress(value)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	flow := makeSharedNetworkFlowHandle(key, value)
	if retain {
		b.retainFlowLocked(flow)
	}
	return OriginalDestination{
		Destination: netip.AddrPortFrom(address, value.Port),
		SourceMAC:   sharedNetworkOriginalMAC(value),
	}, &flow, nil
}

func (b *SharedNetworkBackend) ReleaseFlow(flow *SharedNetworkFlowHandle) error {
	if b == nil || flow == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil
	}
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	if !b.releaseFlowReferenceLocked(*flow) {
		return nil
	}
	return E.Errors(
		deleteMapIfExists(int(b.runtime.original_to_token_map_fd), unsafe.Pointer(&flow.originalKey)),
		deleteMapIfExists(int(b.runtime.listener_map_fd), unsafe.Pointer(&flow.listenerKey)),
		deleteMapIfExists(int(b.runtime.reply_map_fd), unsafe.Pointer(&flow.replyKey)),
	)
}

func (b *SharedNetworkBackend) ExpirePendingTCPFlows(maxAge time.Duration, limit int) (int, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	if maxAge <= 0 || limit <= 0 {
		return 0, E.New("invalid pending shared-network TCP cleanup parameters")
	}
	var monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		return 0, E.Cause(err, "read monotonic clock for shared-network TCP cleanup")
	}
	now := uint64(monotonic.Nano())
	maxAgeNS := uint64(maxAge)

	b.access.RLock()
	defer b.access.RUnlock()
	if err := b.requireUsableLocked(); err != nil {
		return 0, err
	}
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()

	mapFD := int(b.runtime.original_to_token_map_fd)
	staleFlows := make([]SharedNetworkFlowHandle, 0, limit)
	for range limit {
		var currentKeyPointer unsafe.Pointer
		if b.pendingTCPCursorValid {
			currentKeyPointer = unsafe.Pointer(&b.pendingTCPCursor)
		}
		var nextKey sharedNetworkOriginalKey
		if err := getNextMapKey(mapFD, currentKeyPointer, unsafe.Pointer(&nextKey)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				b.pendingTCPCursorValid = false
				break
			}
			return 0, E.Cause(err, "iterate pending shared-network TCP flows")
		}
		b.pendingTCPCursor = nextKey
		b.pendingTCPCursorValid = true
		if nextKey.Protocol != ProtocolTCP {
			continue
		}
		var token sharedNetworkTokenValue
		if err := lookupMap(mapFD, unsafe.Pointer(&nextKey), unsafe.Pointer(&token)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return 0, E.Cause(err, "lookup pending shared-network TCP flow")
		}
		if !pendingTCPFlowExpired(token.CreatedAtNS, now, maxAgeNS) {
			continue
		}
		flow := makeSharedNetworkFlowHandleFromOriginal(nextKey, token, b.control.ListenerPort)
		if b.flowReferences[flow] == 0 {
			staleFlows = append(staleFlows, flow)
		}
	}

	originalKeys := make([]sharedNetworkOriginalKey, len(staleFlows))
	listenerKeys := make([]sharedNetworkListenerKey, len(staleFlows))
	replyKeys := make([]sharedNetworkReplyKey, len(staleFlows))
	for index, flow := range staleFlows {
		originalKeys[index] = flow.originalKey
		listenerKeys[index] = flow.listenerKey
		replyKeys[index] = flow.replyKey
	}
	cleanupErr := E.Errors(
		deleteMapKeysIfExist(int(b.runtime.original_to_token_map_fd), originalKeys),
		deleteMapKeysIfExist(int(b.runtime.listener_map_fd), listenerKeys),
		deleteMapKeysIfExist(int(b.runtime.reply_map_fd), replyKeys),
	)
	if cleanupErr != nil {
		return 0, cleanupErr
	}
	return len(staleFlows), nil
}

func pendingTCPFlowExpired(createdAtNS uint64, now uint64, maxAgeNS uint64) bool {
	return createdAtNS != 0 && now >= createdAtNS && now-createdAtNS >= maxAgeNS
}

func (b *SharedNetworkBackend) retainFlowLocked(flow SharedNetworkFlowHandle) {
	if b.flowReferences == nil {
		b.flowReferences = make(map[SharedNetworkFlowHandle]uint32)
	}
	b.flowReferences[flow]++
}

func (b *SharedNetworkBackend) releaseFlowReferenceLocked(flow SharedNetworkFlowHandle) bool {
	references := b.flowReferences[flow]
	if references == 0 {
		return false
	}
	if references > 1 {
		b.flowReferences[flow] = references - 1
		return false
	}
	delete(b.flowReferences, flow)
	return true
}

func deleteMapIfExists(mapFD int, key unsafe.Pointer) error {
	err := deleteMap(mapFD, key)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func deleteMapKeysIfExist[T any](mapFD int, keys []T) error {
	if len(keys) == 0 {
		return nil
	}
	processed, err := deleteMapBatch(
		mapFD,
		unsafe.Pointer(&keys[0]),
		uint32(len(keys)),
		unsafe.Sizeof(keys[0]),
		&sharedFlowDeleteBatchSupport,
	)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	for index := int(processed); index < len(keys); index++ {
		if err = deleteMapIfExists(mapFD, unsafe.Pointer(&keys[index])); err != nil {
			return err
		}
	}
	return nil
}
