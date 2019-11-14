// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mpsquic

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

var _ net.Conn = (*SCIONFlexConn)(nil)
var _ net.PacketConn = (*SCIONFlexConn)(nil)
var _ snet.Conn = (*SCIONFlexConn)(nil)

type SCIONFlexConn struct {
	conn snet.PacketConn
	// Local, remote and bind SCION addresses (IA, L3, L4)
	laddr *snet.Addr
	raddr *snet.Addr
	baddr *snet.Addr

	// svc address
	svc addr.HostSVC

	// Reference to SCION networking context
	scionNet *snet.SCIONNetwork

	// Describes L3 and L4 protocol; currently only udp4 is implemented
	net string

	// localIA is the local AS. Path and overlay resolution differs between
	// destinations residing in the local AS, and destinations residing in
	// other ASes.
	localIA addr.IA

	// pathResolver is a source of paths and overlay addresses for snet.
	pathResolver pathmgr.Resolver
	// monitor tracks contexts created for sciond
	monitor Monitor

	writeMtx    sync.Mutex
	readMtx     sync.Mutex
	writeBuffer common.RawBytes
	readBuffer  common.RawBytes

	raddrs []*snet.Addr // Backup raddrs, w path, includes raddr
}

func newSCIONFlexConn(network string, n *snet.SCIONNetwork, svc addr.HostSVC, laddr *snet.Addr, baddr *snet.Addr, pr pathmgr.Resolver, conn snet.PacketConn, raddrs []*snet.Addr) *SCIONFlexConn {
	c := &SCIONFlexConn{
		conn:         conn,

		laddr:        laddr.Copy(),
		raddr:        raddrs[0],
		baddr:        baddr,

		svc:          svc,

		scionNet:     n,

		net:          network,

		localIA:      laddr.IA,

		pathResolver: pr,

		monitor:      NewMonitor(),

		writeBuffer:  make(common.RawBytes, common.MaxMTU),
		readBuffer:   make(common.RawBytes, common.MaxMTU),

		raddrs:       raddrs,
	}
	return c
}

// Implements the io.Reader interface and parts of scionConnReader functionality

func (c *SCIONFlexConn) ReadFromSCION(b []byte) (int, *snet.Addr, error) {
	return c.read(b)
}

func (c *SCIONFlexConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.read(b)
}

func (c *SCIONFlexConn) Read(b []byte) (int, error) {
	n, _, err := c.read(b)
	return n, err
}

func (c *SCIONFlexConn) read(b []byte) (int, *snet.Addr, error) {
	if c.scionNet == nil {
		return 0, nil, common.NewBasicError("SCION network not initialized", nil)
	}

	c.readMtx.Lock()
	defer c.readMtx.Unlock()

	pkt := snet.SCIONPacket{
		Bytes: snet.Bytes(c.readBuffer),
	}
	var lastHop overlay.OverlayAddr
	err := c.conn.ReadFrom(&pkt, &lastHop)
	if err != nil {
		return 0, nil, err
	}

	// Copy data, extract address
	n, err := pkt.Payload.WritePld(b)
	if err != nil {
		return 0, nil, common.NewBasicError("Unable to copy payload", err)
	}

	var remote *snet.Addr
	// On UDP4 network we can get either UDP traffic or SCMP messages
	if c.net == "udp4" {
		// Extract remote address
		remote = &snet.Addr{
			IA: pkt.Source.IA,
		}

		// Extract path
		if pkt.Path != nil {
			remote.Path = pkt.Path.Copy()
			if err = remote.Path.Reverse(); err != nil {
				return 0, nil,
					common.NewBasicError("Unable to reverse path on received packet", err)
			}
		}

		// Copy the address to prevent races. See
		// https://github.com/scionproto/scion/issues/1659.
		remote.NextHop = lastHop.Copy()

		var err error
		var l4i addr.L4Info
		switch hdr := pkt.L4Header.(type) {
		case *l4.UDP:
			l4i = addr.NewL4UDPInfo(hdr.SrcPort)
		case *scmp.Hdr:
			l4i = addr.NewL4SCMPInfo()
		default:
			err = common.NewBasicError("Unexpected SCION L4 protocol", nil,
				"expected", "UDP or SCMP", "actual", pkt.L4Header.L4Type())
		}
		// Copy the address to prevent races. See
		// https://github.com/scionproto/scion/issues/1659.
		remote.Host = &addr.AppAddr{L3: pkt.Source.Host.Copy(), L4: l4i}
		return n, remote, err
	}
	return 0, nil, common.NewBasicError("Unknown network", nil, "net", c.net)
}

func (c *SCIONFlexConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// Implements the io.Writer interface and parts of snet.scionConnWriter functionality

// Possible write errors
const (
	ErrNoAddr               = "remote address required, but none set"
	ErrDuplicateAddr        = "remote address specified as argument, but address set in conn"
	ErrAddressIsNil         = "address is nil"
	ErrNoApplicationAddress = "SCION host address is missing"
	ErrExtraPath            = "path set, but none required for local AS"
	ErrBadOverlay           = "overlay address not set, and construction from SCION address failed"
	ErrMustHavePath         = "overlay address set, but no path set"
	ErrPath                 = "no path set, and error during path resolution"
)

const (
	DefaultPathQueryTimeout = 5 * time.Second
)

func (c *SCIONFlexConn) WriteToSCION(b []byte, raddr *snet.Addr) (int, error) {
	return c.write(b, c.raddr)
}

func (c *SCIONFlexConn) WriteTo(b []byte, raddr net.Addr) (int, error) {
	_, ok := raddr.(*snet.Addr)
	if !ok {
		return 0, common.NewBasicError("Unable to write to non-SCION address", nil, "addr", raddr)
	}
	return c.WriteToSCION(b, c.raddr)
}

func (c *SCIONFlexConn) Write(b []byte) (n int, err error) {
	return c.write(b, nil)
}

func (c *SCIONFlexConn) write(b []byte, raddr *snet.Addr) (int, error) {

	if raddr == nil {
		var err error
		raddr, err = c.resolveAddrPair(c.raddr, raddr)
		if err != nil {
			return 0, err
		}
	}
	return c.writeWithLock(b, raddr)
}

func (c *SCIONFlexConn) writeWithLock(b []byte, raddr *snet.Addr) (int, error) {
	c.writeMtx.Lock()
	defer c.writeMtx.Unlock()
	pkt := &snet.SCIONPacket{
		Bytes: snet.Bytes(c.writeBuffer),
		SCIONPacketInfo: snet.SCIONPacketInfo{
			Destination: snet.SCIONAddress{IA: raddr.IA, Host: raddr.Host.L3},
			Source:      snet.SCIONAddress{IA: c.laddr.IA, Host: c.laddr.Host.L3},
			Path:        raddr.Path,
			L4Header: &l4.UDP{
				SrcPort:  c.laddr.Host.L4.Port(),
				DstPort:  raddr.Host.L4.Port(),
				TotalLen: uint16(l4.UDPLen + len(b)),
			},
			Payload: common.RawBytes(b),
		},
	}

	//printHFDetails(raddr.Path)

	if err := c.conn.WriteTo(pkt, raddr.NextHop); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *SCIONFlexConn) SetWriteDeadline(t time.Time) error {
	if err := c.conn.SetWriteDeadline(t); err != nil {
		return err
	}
	c.monitor.SetDeadline(t)
	return nil
}

func (c *SCIONFlexConn) resolveAddrPair(connAddr, argAddr *snet.Addr) (*snet.Addr, error) {
	switch {
	case connAddr == nil && argAddr == nil:
		return nil, common.NewBasicError(ErrNoAddr, nil)
	case connAddr != nil && argAddr != nil:
		return nil, common.NewBasicError(ErrDuplicateAddr, nil)
	case connAddr != nil:
		return c.resolveAddr(connAddr)
	default:
		// argAddr != nil
		return c.resolveAddr(argAddr)
	}
}

func (c *SCIONFlexConn) resolveAddr(address *snet.Addr) (*snet.Addr, error) {
	if address == nil {
		return nil, common.NewBasicError(ErrAddressIsNil, nil)
	}
	if address.Host == nil {
		return nil, common.NewBasicError(ErrNoApplicationAddress, nil)
	}
	if c.localIA.Equal(address.IA) {
		return c.resolveLocalDestination(address)
	}
	return c.resolveRemoteDestination(address)
}

func (r *SCIONFlexConn) resolveLocalDestination(address *snet.Addr) (*snet.Addr, error) {
	if address.Path != nil {
		return nil, common.NewBasicError(ErrExtraPath, nil)
	}
	if address.NextHop == nil {
		return addOverlayFromScionAddress(address)
	}
	return address, nil
}


func (c *SCIONFlexConn) resolveRemoteDestination(address *snet.Addr) (*snet.Addr, error) {
	switch {
	case address.Path != nil && address.NextHop == nil:
		return nil, common.NewBasicError(ErrBadOverlay, nil)
	case address.Path == nil && address.NextHop != nil:
		return nil, common.NewBasicError(ErrMustHavePath, nil)
	case address.Path != nil:
		return address, nil
	default:
		return c.addPath(address)
	}
}

func (c *SCIONFlexConn) addPath(address *snet.Addr) (*snet.Addr, error) {
	var err error
	address = address.Copy()
	ctx, cancelF := c.monitor.WithTimeout(context.Background(), DefaultPathQueryTimeout)
	defer cancelF()
	address.NextHop, address.Path, err = c.GetPath(ctx, c.localIA, address.IA)
	if err != nil {
		return nil, common.NewBasicError(ErrPath, nil)
	}
	return address, nil
}

func addOverlayFromScionAddress(address *snet.Addr) (*snet.Addr, error) {
	var err error
	address = address.Copy()
	address.NextHop, err = overlay.NewOverlayAddr(address.Host.L3,
		addr.NewL4UDPInfo(overlay.EndhostPort))
	if err != nil {
		return nil, common.NewBasicError(ErrBadOverlay, err)
	}
	return address, nil
}

// Implements part of the snet.pathSource functionality

const (
	ErrNoResolver = "no resolver set"
	ErrNoPath     = "path not found"
	ErrInitPath   = "raw forwarding path offsets could not be initialized"
)

func (c *SCIONFlexConn) GetPath(ctx context.Context,
	src, dst addr.IA) (*overlay.OverlayAddr, *spath.Path, error) {

	if c.pathResolver == nil {
		return nil, nil, common.NewBasicError(ErrNoResolver, nil)
	}
	paths := c.pathResolver.Query(ctx, src, dst, sciond.PathReqFlags{})
	sciondPath := paths.GetAppPath("")
	if sciondPath == nil {
		return nil, nil, common.NewBasicError(ErrNoPath, nil)
	}
	path := &spath.Path{Raw: sciondPath.Entry.Path.FwdPath}
	if err := path.InitOffsets(); err != nil {
		return nil, nil, common.NewBasicError(ErrInitPath, nil)
	}
	overlayAddr, err := sciondPath.Entry.HostInfo.Overlay()
	if err != nil {
		return nil, nil, common.NewBasicError(ErrBadOverlay, nil)
	}
	return overlayAddr, path, nil
}

// Implements part of the net.Conn, net.PacketConn interfaces (and snet.Conn)

func (c *SCIONFlexConn) Close() error {
	return c.conn.Close()
}

func (c *SCIONFlexConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *SCIONFlexConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *SCIONFlexConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	if err := c.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

// Implements part of the snet.Conn interface

func (c *SCIONFlexConn) BindAddr() net.Addr {
	return c.baddr
}

func (c *SCIONFlexConn) SVC() addr.HostSVC {
	return c.svc
}

// Implements part of the snet.scionConnBase functionality

func (c *SCIONFlexConn) BindSnetAddr() *snet.Addr {
	return c.baddr
}

func (c *SCIONFlexConn) LocalSnetAddr() *snet.Addr {
	return c.laddr
}

func (c *SCIONFlexConn) RemoteSnetAddr() *snet.Addr {
	return c.raddr
}
