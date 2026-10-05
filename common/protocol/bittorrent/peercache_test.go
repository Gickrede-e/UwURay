package bittorrent

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func key(user, peer string) peerKey {
	return peerKey{user: user, peer: netip.MustParseAddrPort(peer)}
}

func TestPeerCache(t *testing.T) {
	c := newPeerCache()
	now := time.Now()

	c.add(key("a", "203.0.113.5:51413"), now)
	if !c.has(key("a", "203.0.113.5:51413"), now.Add(peerCacheTTL-time.Second)) {
		t.Fatal("expected a cache hit within TTL")
	}
	if c.has(key("b", "203.0.113.5:51413"), now) {
		t.Fatal("expected another user not to hit the entry")
	}
	if c.has(key("a", "203.0.113.5:51413"), now.Add(peerCacheTTL+time.Second)) {
		t.Fatal("expected the entry to expire after TTL")
	}

	c.add(key("a", "203.0.113.5:51413"), now.Add(5*time.Minute))
	if !c.has(key("a", "203.0.113.5:51413"), now.Add(peerCacheTTL+time.Second)) {
		t.Fatal("expected fresh evidence to extend the entry")
	}

	for i := range peerCacheUserBudget + 10 {
		c.add(peerKey{"b", netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(10000+i))}, now)
	}
	if c.has(peerKey{"b", netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(10000+peerCacheUserBudget))}, now) {
		t.Fatal("expected the user budget to stop new entries")
	}
	c.add(key("c", "198.51.100.2:6881"), now)
	if !c.has(key("c", "198.51.100.2:6881"), now) {
		t.Fatal("expected another user to have its own budget")
	}
}

func TestPeerCacheFull(t *testing.T) {
	c := newPeerCache()
	now := time.Now()

	for i := range peerCacheMax {
		c.peers[peerKey{"old", netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), uint16(i))}] = now.Add(-time.Second)
	}
	c.lastSweep = now.Add(-2 * peerCacheFullSweep)

	c.add(key("a", "203.0.113.5:51413"), now)
	if !c.has(key("a", "203.0.113.5:51413"), now) {
		t.Fatal("expected a full cache of expired entries to be swept and accept new peers")
	}
}

func TestPeerFromContext(t *testing.T) {
	cases := []struct {
		name    string
		inbound *session.Inbound
		dest    net.Destination
		user    string
		ok      bool
	}{
		{"peer", nil, net.TCPDestination(net.ParseAddress("203.0.113.5"), 51413), "", true},
		{"ipv6 peer", nil, net.TCPDestination(net.ParseAddress("2a00:1450::1"), 51413), "", true},
		{"user", &session.Inbound{User: &protocol.MemoryUser{Email: "u@x"}, Source: net.TCPDestination(net.ParseAddress("192.0.2.9"), 1)},
			net.TCPDestination(net.ParseAddress("203.0.113.5"), 51413), "u@x", true},
		{"anonymous user", &session.Inbound{Source: net.TCPDestination(net.ParseAddress("192.0.2.9"), 1)},
			net.TCPDestination(net.ParseAddress("203.0.113.5"), 51413), "192.0.2.9", true},
		{"well-known port", nil, net.TCPDestination(net.ParseAddress("203.0.113.5"), 443), "", false},
		{"stun port", nil, net.UDPDestination(net.ParseAddress("203.0.113.5"), 3478), "", false},
		{"private address", nil, net.TCPDestination(net.ParseAddress("192.168.1.2"), 51413), "", false},
		{"cgnat address", nil, net.TCPDestination(net.ParseAddress("100.64.1.2"), 51413), "", false},
		{"fake dns address", nil, net.TCPDestination(net.ParseAddress("198.18.0.7"), 51413), "", false},
		{"domain", nil, net.TCPDestination(net.ParseAddress("example.com"), 51413), "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: c.dest}})
			if c.inbound != nil {
				ctx = session.ContextWithInbound(ctx, c.inbound)
			}
			k, ok := peerFromContext(ctx)
			if ok != c.ok {
				t.Fatalf("expected %v, got %v", c.ok, ok)
			}
			if ok && k.user != c.user {
				t.Fatalf("expected user %q, got %q", c.user, k.user)
			}
		})
	}
}
