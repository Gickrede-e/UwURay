package dispatcher_test

import (
	"bytes"
	"context"
	"testing"

	. "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

const xrayKey core.XrayKey = 1

func TestSnifferBitTorrentPeerCache(t *testing.T) {
	v, err := core.New(&core.Config{})
	common.Must(err)
	ctx := context.WithValue(context.Background(), xrayKey, v)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{User: &protocol.MemoryUser{Email: "sniffer-test"}})
	peer := net.ParseAddress("203.0.113.77")
	udpCtx := session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.UDPDestination(peer, 51413)}})
	tcpCtx := session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(peer, 51413)}})
	encrypted := bytes.Repeat([]byte{0x8f, 0x3a, 0xd1, 0x5c}, 40) // MSE-like, no sniffer recognizes it

	if _, err := NewSniffer(tcpCtx).Sniff(tcpCtx, encrypted, net.Network_TCP); err == nil {
		t.Fatal("expected unknown content before the peer is seen")
	}

	dht := []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
	if r, err := NewSniffer(udpCtx).Sniff(udpCtx, dht, net.Network_UDP); err != nil || r.Protocol() != "bittorrent" {
		t.Fatalf("expected bittorrent, got %v, %v", r, err)
	}

	if r, err := NewSniffer(tcpCtx).Sniff(tcpCtx, encrypted, net.Network_TCP); err != nil || r.Protocol() != "bittorrent-cache" {
		t.Fatalf("expected bittorrent-cache, got %v, %v", r, err)
	}

	// content another sniffer may still recognize is not claimed by the cache
	if _, err := NewSniffer(tcpCtx).Sniff(tcpCtx, []byte("GET"), net.Network_TCP); err != common.ErrNoClue {
		t.Fatalf("expected ErrNoClue for a partial HTTP request, got %v", err)
	}
}
