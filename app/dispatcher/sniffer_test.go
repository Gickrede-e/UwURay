package dispatcher_test

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"testing"

	. "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	feature_stats "github.com/xtls/xray-core/features/stats"
)

const xrayKey core.XrayKey = 1

var testRuns atomic.Int32

func TestSnifferBitTorrentPeerCache(t *testing.T) {
	user := fmt.Sprint("sniffer-test-", testRuns.Add(1)) // the peer cache is process-wide
	v, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&stats.Config{})}})
	common.Must(err)
	flow := func(email string, dest net.Destination) context.Context {
		ctx := session.ContextWithInbound(context.WithValue(context.Background(), xrayKey, v),
			&session.Inbound{User: &protocol.MemoryUser{Email: email}})
		return session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
	}
	sniff := func(ctx context.Context, payload []byte, network net.Network) (SniffResult, error) {
		return NewSniffer(ctx).Sniff(ctx, payload, network)
	}
	peer := net.ParseAddress("203.0.113.77")
	udpCtx := flow(user, net.UDPDestination(peer, 51413))
	tcpCtx := flow(user, net.TCPDestination(peer, 51413))
	encrypted := bytes.Repeat([]byte{0x8f, 0x3a, 0xd1, 0x5c}, 40) // no sniffer recognizes it, not MSE shaped either
	dht := []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")

	if _, err := sniff(tcpCtx, encrypted, net.Network_TCP); err == nil {
		t.Fatal("expected unknown content before the peer is seen")
	}

	if r, err := sniff(udpCtx, dht, net.Network_UDP); err != nil || r.Protocol() != "bittorrent" {
		t.Fatalf("expected bittorrent, got %v, %v", r, err)
	}

	if r, err := sniff(tcpCtx, encrypted, net.Network_TCP); err != nil || r.Protocol() != "bittorrent-cache" {
		t.Fatalf("expected bittorrent-cache, got %v, %v", r, err)
	}

	// the user is now marked: MSE-shaped TCP to a peer never seen before is recognized too, for this user only
	handshake := make([]byte, 200)
	rand.NewChaCha8([32]byte{1}).Read(handshake)
	newPeer := net.TCPDestination(net.ParseAddress("203.0.113.78"), 40001)
	if r, err := sniff(flow(user, newPeer), handshake, net.Network_TCP); err != nil || r.Protocol() != "bittorrent-mse" {
		t.Fatalf("expected bittorrent-mse, got %v, %v", r, err)
	}
	if _, err := sniff(flow(user, newPeer), handshake[:50], net.Network_TCP); err != common.ErrNoClue {
		t.Fatalf("expected a short first read of a marked user to wait for more data, got %v", err)
	}
	if _, err := sniff(flow(user+"-other", newPeer), handshake, net.Network_TCP); err == nil {
		t.Fatal("expected an unmarked user's encrypted flow to stay unknown")
	}

	// a key online from many addresses is shared: it may be marked, but MSE shape is not applied to it
	shared := user + "-shared"
	om, err := v.GetFeature(feature_stats.ManagerType()).(feature_stats.Manager).GetOrRegisterOnlineMap("user>>>" + shared + ">>>online")
	common.Must(err)
	for i := range 9 {
		om.AddIP(fmt.Sprint("192.0.2.", i+1))
	}
	if _, err := sniff(flow(shared, net.UDPDestination(peer, 51413)), dht, net.Network_UDP); err != nil {
		t.Fatalf("expected the shared key's DHT to be sniffed, got %v", err)
	}
	if _, err := sniff(flow(shared, newPeer), handshake, net.Network_TCP); err == nil {
		t.Fatal("expected a shared key's encrypted flow to a new peer to stay unknown")
	}

	// content another sniffer may still recognize is not claimed by the cache
	if _, err := sniff(tcpCtx, []byte("GET"), net.Network_TCP); err != common.ErrNoClue {
		t.Fatalf("expected ErrNoClue for a partial HTTP request, got %v", err)
	}
}
