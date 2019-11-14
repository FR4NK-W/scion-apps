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

// "Multiple paths" QUIC/SCION implementation.
package mpsquic

import (
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/lib/sock/reliable"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"net"
)

const (
	defKeyPath = "gen-certs/tls.key"
	defPemPath = "gen-certs/tls.pem"
)

// A Listener of QUIC
type server struct {
	tlsConf *tls.Config
	config  *quic.Config

	conn net.PacketConn
}

var (
	activePacketConn net.PacketConn
	qsessions []quic.Session
	// Don't verify the server's cert, as we are not using the TLS PKI.
	cliTlsCfg = &tls.Config{InsecureSkipVerify: true}
	srvTlsCfg = &tls.Config{}

	flexConn *SCIONFlexConn
)

func Init(keyPath, pemPath string) error {
	if keyPath == "" {
		keyPath = defKeyPath
	}
	if pemPath == "" {
		pemPath = defPemPath
	}
	cert, err := tls.LoadX509KeyPair(pemPath, keyPath)
	if err != nil {
		return common.NewBasicError("mpsquic: Unable to load TLS cert/key", err)
	}
	srvTlsCfg.Certificates = []tls.Certificate{cert}
	return nil
}

func DialSCIONTransport(network *snet.SCIONNetwork, laddr, raddr *snet.Addr,
	quicConfig *quic.Config) (quic.Session, error) {

	return DialSCIONTransportWithBindSVC(network, laddr, raddr, nil, addr.SvcNone, quicConfig)
}

func DialMPSCIONTransport(network *snet.SCIONNetwork, laddr *snet.Addr, raddrs []*snet.Addr,
	quicConfig *quic.Config) (quic.Session, error) {

	return DialMPSCIONTransportWithBindSVC(network, laddr, raddrs, nil, addr.SvcNone, quicConfig)
}

func DialSCIONTransportWithBindSVC(network *snet.SCIONNetwork, laddr, raddr, baddr *snet.Addr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Session, error) {

	sconn, err := sListen(network, laddr, baddr, svc)
	if err != nil {
		return nil, err
	}
	// Use dummy hostname, as it's used for SNI, and we're not doing cert verification.
	return quic.Dial(sconn, raddr, "host:0", cliTlsCfg, quicConfig)
}

func DialMPSCIONTransportWithBindSVC(network *snet.SCIONNetwork, laddr *snet.Addr, raddrs []*snet.Addr, baddr *snet.Addr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Session, error) {

	if network == nil {
		network = snet.DefNetwork
	}

	dispatcherSocket := "/run/shm/dispatcher/default.sock"
	reliableDispatcher := reliable.NewDispatcherService(dispatcherSocket)
	pktDisp := &snet.DefaultPacketDispatcherService{
		Dispatcher: reliableDispatcher,
	}
	packetConn, port, err := pktDisp.RegisterTimeout(laddr.IA,
		laddr.Host, nil, svc, 0)
	_ = port // Not used right now, just name it
	flexConn = newSCIONFlexConn("udp4", network, svc, laddr, baddr, network.PathResolver(), packetConn, raddrs)


	activePacketConn = flexConn
	// Use dummy hostname, as it's used for SNI, and we're not doing cert verification.
	qsession, err := quic.Dial(activePacketConn, flexConn.raddr, "host:0", cliTlsCfg, quicConfig)
	if err != nil {
		return nil, err
	}
	qsessions = append(qsessions, qsession)
	return qsessions[0], nil
}

// This switches between different SCION paths as given by the SCION address with path structs in raddrs
func SwitchMPSCIONConn(currentQuicSession quic.Session) (quic.Session, error) {
	// Right now, the QUIC session is returned unmodified
	// Still passing it in, since it might change later
	for i := range flexConn.raddrs {
		if flexConn.raddr != flexConn.raddrs[i] {
			fmt.Printf("Previous path: %v\n", flexConn.raddr.Path)
			fmt.Printf("New path: %v\n", flexConn.raddrs[i].Path)
			flexConn.raddr = flexConn.raddrs[i]
			return currentQuicSession, nil
		}
	}

	return nil, common.NewBasicError("mpsquic: No fallback connection available.", nil)
}

func ListenSCIONTransport(network *snet.SCIONNetwork, laddr *snet.Addr,
	quicConfig *quic.Config) (quic.Listener, error) {

	return ListenSCIONTransportWithBindSVC(network, laddr, nil, addr.SvcNone, quicConfig)
}

func ListenSCIONTransportWithBindSVC(network *snet.SCIONNetwork, laddr, baddr *snet.Addr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Listener, error) {

	if len(srvTlsCfg.Certificates) == 0 {
		return nil, common.NewBasicError("mpsquic: No server TLS certificate configured", nil)
	}
	sconn, err := sListen(network, laddr, baddr, svc)
	if err != nil {
		return nil, err
	}
	qListener, err := quic.Listen(sconn, srvTlsCfg, quicConfig)
	return qListener, err
}

func sListen(network *snet.SCIONNetwork, laddr, baddr *snet.Addr,
	svc addr.HostSVC) (snet.Conn, error) {

	if network == nil {
		network = snet.DefNetwork
	}
	return network.ListenSCIONWithBindSVC("udp4", laddr, baddr, svc, 0)
}
