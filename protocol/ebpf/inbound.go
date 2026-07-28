//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const listenPort = 65532

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.EBPFInboundOptions](registry, C.TypeEBPF, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx               context.Context
	router            adapter.ConnectionRouterEx
	logger            log.ContextLogger
	networkManager    adapter.NetworkManager
	listener          *listener.Listener
	udpNat            *udpnat.Service
	backend           *ECommon.Backend
	protectRegistered bool

	bindingAccess sync.RWMutex
	bindings      map[udpBindingKey]netip.Addr
	connectedUDP  map[netip.AddrPort]bool
}

type udpBindingKey struct {
	client      netip.AddrPort
	destination netip.AddrPort
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, _ option.EBPFInboundOptions) (adapter.Inbound, error) {
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	inbound := &Inbound{
		Adapter:        inbound.NewAdapter(C.TypeEBPF, tag),
		ctx:            ctx,
		router:         router,
		logger:         logger,
		networkManager: networkManager,
		bindings:       make(map[udpBindingKey]netip.Addr),
		connectedUDP:   make(map[netip.AddrPort]bool),
	}
	inbound.udpNat = udpnat.New(inbound, inbound.preparePacketConnection, C.UDPTimeout, false)
	inbound.listener = listener.New(listener.Options{
		Context: ctx,
		Logger:  logger,
		Network: []string{N.NetworkTCP, N.NetworkUDP},
		Listen: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
			ListenPort: listenPort,
		},
		ConnectionHandler:   inbound,
		OOBPacketHandler:    inbound,
		DisablePacketOutput: true,
		SocketControl:       inbound.socketControl(),
	})
	return inbound, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		backend, err := ECommon.Prepare("", listenPort)
		if err != nil {
			return err
		}
		i.backend = backend
		if err = i.networkManager.RegisterSocketProtectFunc(backend.ProtectFunc()); err != nil {
			_ = backend.Close()
			i.backend = nil
			return err
		}
		i.protectRegistered = true
	case adapter.StartStateStart:
		if i.backend == nil {
			return E.New("eBPF backend is not initialized")
		}
		if err := i.listener.Start(); err != nil {
			_ = i.listener.Close()
			i.unregisterSocketProtector()
			_ = i.backend.Close()
			i.backend = nil
			return err
		}
		if err := i.backend.Attach(); err != nil {
			_ = i.listener.Close()
			i.unregisterSocketProtector()
			_ = i.backend.Close()
			i.backend = nil
			return err
		}
		i.logger.Info("eBPF inbound attached to ", i.backend.CgroupPath())
	}
	return nil
}

func (i *Inbound) Close() error {
	i.unregisterSocketProtector()
	var backendErr error
	if i.backend != nil {
		backendErr = i.backend.Close()
		i.backend = nil
	}
	i.udpNat.Purge()
	return E.Errors(backendErr, i.listener.Close())
}

func (i *Inbound) unregisterSocketProtector() {
	if !i.protectRegistered {
		return
	}
	i.networkManager.UnregisterSocketProtectFunc()
	i.protectRegistered = false
}

func (i *Inbound) InterfaceUpdated() {
	i.udpNat.Purge()
}

func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if i.backend == nil {
		conn.Close()
		return
	}
	original, err := i.backend.LookupOriginal(
		ECommon.ProtocolTCP,
		M.SocksaddrFromNet(conn.LocalAddr()).AddrPort(),
	)
	if err != nil {
		i.logger.ErrorContext(ctx, "lookup TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	i.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	if i.backend == nil {
		return
	}
	tokenAddress, err := tokenAddressFromOOB(oob)
	if err != nil {
		i.logger.Warn("read UDP token address: ", err)
		return
	}
	client := source.AddrPort()
	token := netip.AddrPortFrom(tokenAddress, listenPort)
	original, err := i.backend.LookupOriginal(ECommon.ProtocolUDP, token)
	if err != nil {
		i.logger.Warn("lookup UDP original destination: ", err)
		return
	}
	i.bindingAccess.Lock()
	i.bindings[udpBindingKey{client: client, destination: original.Destination}] = tokenAddress
	i.bindingAccess.Unlock()
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), original.ConnectedUDP)
}

func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Source:      source,
		Destination: destination,
	}
	i.bindingAccess.RLock()
	metadata.UDPConnect = i.connectedUDP[source.AddrPort()]
	i.bindingAccess.RUnlock()
	i.logger.InfoContext(ctx, "inbound packet connection from ", source)
	i.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	connectedUDP, _ := userData.(bool)
	ctx := log.ContextWithNewID(i.ctx)
	client := source.AddrPort()
	i.bindingAccess.Lock()
	i.connectedUDP[client] = connectedUDP
	i.bindingAccess.Unlock()
	writer := &udpPacketWriter{
		inbound: i,
		client:  client,
	}
	return true, ctx, writer, func(error) {
		i.deleteBindings(writer.client)
	}
}

func (i *Inbound) socketControl() control.Func {
	return func(network string, address string, rawConn syscall.RawConn) error {
		if network != "udp4" {
			return nil
		}
		return control.Raw(rawConn, func(fd uintptr) error {
			return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
		})
	}
}

func (i *Inbound) tokenFor(client netip.AddrPort, destination netip.AddrPort) (netip.Addr, bool) {
	i.bindingAccess.RLock()
	token, loaded := i.bindings[udpBindingKey{client: client, destination: destination}]
	i.bindingAccess.RUnlock()
	return token, loaded
}

func (i *Inbound) deleteBindings(client netip.AddrPort) {
	i.bindingAccess.Lock()
	for key := range i.bindings {
		if key.client == client {
			delete(i.bindings, key)
		}
	}
	delete(i.connectedUDP, client)
	i.bindingAccess.Unlock()
}

type udpPacketWriter struct {
	inbound *Inbound
	client  netip.AddrPort
}

func (w *udpPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	token, loaded := w.inbound.tokenFor(w.client, destination.AddrPort())
	if !loaded {
		return E.New("missing UDP token binding for ", destination)
	}
	controlMessage := (&ipv4.ControlMessage{Src: net.IP(token.AsSlice())}).Marshal()
	_, _, err := w.inbound.listener.UDPConn().WriteMsgUDPAddrPort(buffer.Bytes(), controlMessage, w.client)
	return err
}

func tokenAddressFromOOB(oob []byte) (netip.Addr, error) {
	var controlMessage ipv4.ControlMessage
	if err := controlMessage.Parse(oob); err != nil {
		return netip.Addr{}, err
	}
	address, loaded := netip.AddrFromSlice(controlMessage.Dst)
	if !loaded || !address.Is4() {
		return netip.Addr{}, E.New("IPv4 packet info is missing")
	}
	return address.Unmap(), nil
}
