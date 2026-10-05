package bittorrent

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestPeerCache(t *testing.T) {
	c := newPeerCache()
	now := time.Now()
	peer := netip.MustParseAddrPort("203.0.113.5:51413")

	c.add(peer, "a", now)
	if !c.has(peer, now.Add(peerCacheTTL-time.Second)) {
		t.Fatal("expected a cache hit within TTL")
	}
	if c.has(peer, now.Add(peerCacheTTL+time.Second)) {
		t.Fatal("expected the entry to expire after TTL")
	}

	c.add(peer, "a", now.Add(5*time.Minute))
	if !c.has(peer, now.Add(peerCacheTTL+time.Second)) {
		t.Fatal("expected fresh evidence to extend the entry")
	}

	for i := range peerCacheEmailBudget + 10 {
		c.add(netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(10000+i)), "b", now)
	}
	if c.has(netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(10000+peerCacheEmailBudget)), now) {
		t.Fatal("expected the email budget to stop new entries")
	}
	c.add(netip.MustParseAddrPort("198.51.100.2:6881"), "c", now)
	if !c.has(netip.MustParseAddrPort("198.51.100.2:6881"), now) {
		t.Fatal("expected another email to have its own budget")
	}
}

func TestPeerFromContext(t *testing.T) {
	cases := []struct {
		name string
		dest net.Destination
		ok   bool
	}{
		{"peer", net.TCPDestination(net.ParseAddress("203.0.113.5"), 51413), true},
		{"ipv4-mapped ipv6", net.TCPDestination(net.ParseAddress("::ffff:203.0.113.5"), 51413), true},
		{"well-known port", net.TCPDestination(net.ParseAddress("203.0.113.5"), 443), false},
		{"stun port", net.UDPDestination(net.ParseAddress("203.0.113.5"), 3478), false},
		{"private address", net.TCPDestination(net.ParseAddress("192.168.1.2"), 51413), false},
		{"domain", net.TCPDestination(net.ParseAddress("example.com"), 51413), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: c.dest}})
			if _, ok := peerFromContext(ctx); ok != c.ok {
				t.Fatalf("expected %v, got %v", c.ok, ok)
			}
		})
	}
}
