package bittorrent

import (
	"bytes"
	"context"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func key(user, peer string) peerKey {
	return peerKey{user: user, peer: netip.MustParseAddrPort(peer)}
}

// randomBytes returns deterministic random-looking bytes
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.NewChaCha8([32]byte{1}).Read(b)
	return b
}

// withPeers runs the test against a fresh process-wide cache and restores the previous one
func withPeers(t *testing.T) {
	old := peers
	peers = newPeerCache()
	t.Cleanup(func() { peers = old })
}

func flow(email string, dest net.Destination) context.Context {
	ctx := context.Background()
	if email != "" {
		ctx = session.ContextWithInbound(ctx, &session.Inbound{User: &protocol.MemoryUser{Email: email}})
	}
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
}

func TestPeerCache(t *testing.T) {
	c := newPeerCache()
	now := time.Now()

	c.add(key("a", "203.0.113.5:51413"), now)
	if cached, _ := c.lookup(key("a", "203.0.113.5:51413"), now.Add(peerCacheTTL-time.Second)); !cached {
		t.Fatal("expected a cache hit within TTL")
	}
	if cached, _ := c.lookup(key("b", "203.0.113.5:51413"), now); cached {
		t.Fatal("expected another user not to hit the entry")
	}
	if cached, _ := c.lookup(key("a", "203.0.113.5:51413"), now.Add(peerCacheTTL+time.Second)); cached {
		t.Fatal("expected the entry to expire after TTL")
	}

	c.add(key("a", "203.0.113.5:51413"), now.Add(5*time.Minute))
	if cached, _ := c.lookup(key("a", "203.0.113.5:51413"), now.Add(peerCacheTTL+time.Second)); !cached {
		t.Fatal("expected fresh evidence to extend the entry")
	}

	for i := range peerCacheUserBudget + 10 {
		c.add(peerKey{"b", netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(10000+i))}, now)
	}
	if cached, _ := c.lookup(peerKey{"b", netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(10000+peerCacheUserBudget))}, now); cached {
		t.Fatal("expected the user budget to stop new entries")
	}
	c.add(key("c", "198.51.100.2:6881"), now)
	if cached, _ := c.lookup(key("c", "198.51.100.2:6881"), now); !cached {
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
	if cached, _ := c.lookup(key("a", "203.0.113.5:51413"), now); !cached {
		t.Fatal("expected a full cache of expired entries to be swept and accept new peers")
	}
}

func TestEvidence(t *testing.T) {
	marked := func(c *peerCache, user string, now time.Time) bool {
		_, m := c.lookup(peerKey{user: user}, now)
		return m
	}
	now := time.Now()

	c := newPeerCache()
	c.evidence("strong", "udp:203.0.113.5:6881", false, now)
	if !marked(c, "strong", now.Add(userMarkTTL-time.Second)) {
		t.Fatal("expected strong evidence to mark the user")
	}
	if marked(c, "strong", now.Add(userMarkTTL+time.Second)) {
		t.Fatal("expected the mark to expire after userMarkTTL")
	}
	c.evidence("strong", "udp:203.0.113.5:6881", false, now.Add(30*time.Minute))
	if !marked(c, "strong", now.Add(userMarkTTL+time.Second)) {
		t.Fatal("expected fresh evidence to renew the mark")
	}

	c.evidence("weak", "udp:203.0.113.5:6881", true, now)
	if marked(c, "weak", now) {
		t.Fatal("expected one weak hit not to mark the user")
	}
	c.evidence("weak", "udp:203.0.113.5:6881", true, now.Add(time.Second))
	if marked(c, "weak", now) {
		t.Fatal("expected weak hits to the same target not to mark the user")
	}
	c.evidence("weak", "udp:203.0.113.6:6881", true, now.Add(weakEvidenceWindow+2*time.Second))
	if marked(c, "weak", now) {
		t.Fatal("expected weak hits further apart than weakEvidenceWindow not to mark the user")
	}
	c.evidence("weak", "udp:203.0.113.7:6881", true, now.Add(weakEvidenceWindow+3*time.Second))
	if !marked(c, "weak", now.Add(weakEvidenceWindow+3*time.Second)) {
		t.Fatal("expected weak hits to two targets within weakEvidenceWindow to mark the user")
	}
}

func TestParseMarkSkip(t *testing.T) {
	if parseMarkSkip("") != nil {
		t.Fatal("expected no skip list by default")
	}
	if re := parseMarkSkip("^bridge-"); !re.MatchString("bridge-de") || re.MatchString("19") {
		t.Fatal("expected the skip list to match only bridge accounts")
	}
	if re := parseMarkSkip("("); !re.MatchString("19") {
		t.Fatal("expected an invalid skip list to skip everyone")
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

func TestMSEShaped(t *testing.T) {
	random := randomBytes(608)
	ascii := bytes.Repeat([]byte("GET /announce?info_hash=abc HTTP/1.1\r\n"), 10)
	zeroRun := append([]byte{}, random[:200]...)
	copy(zeroRun[100:], make([]byte, 8))

	cases := []struct {
		name    string
		payload []byte
		mse     bool
	}{
		{"shortest handshake", random[:96], true},
		{"handshake with padding", random[:300], true},
		{"longest handshake", random, true},
		{"too short", random[:95], false},
		{"too long", append(random, random[:1]...), false},
		{"text", ascii[:300], false},
		{"zero run", zeroRun, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mseShaped(c.payload); got != c.mse {
				t.Fatalf("expected %v, got %v", c.mse, got)
			}
		})
	}
}

func TestSniffEncrypted(t *testing.T) {
	withPeers(t)
	handshake := randomBytes(200)
	peer := net.TCPDestination(net.ParseAddress("203.0.113.88"), 40000)

	if _, err := SniffEncrypted(flow("u", peer), handshake); err == nil {
		t.Fatal("expected an unmarked user's encrypted flow to pass")
	}

	RememberPeer(flow("u", net.TCPDestination(net.ParseAddress("tracker.example"), 80)), &SniffHeader{weak: true})
	if _, err := SniffEncrypted(flow("u", peer), handshake); err == nil {
		t.Fatal("expected weak evidence alone not to mark the user")
	}

	// a tracker announce by domain on a well-known port is strong and marks the user
	RememberPeer(flow("u", net.TCPDestination(net.ParseAddress("tracker.example"), 80)), &SniffHeader{})
	if h, err := SniffEncrypted(flow("u", peer), handshake); err != nil || h.Protocol() != "bittorrent-mse" {
		t.Fatalf("expected bittorrent-mse, got %v, %v", h, err)
	}
	if _, err := SniffEncrypted(flow("u", peer), handshake[:50]); err != common.ErrNoClue {
		t.Fatalf("expected a short first read of a marked user to wait for more data, got %v", err)
	}
	if _, err := SniffEncrypted(flow("u", peer), bytes.Repeat([]byte("x"), 200)); err == nil {
		t.Fatal("expected a non-MSE-shaped flow of a marked user to pass")
	}
	if _, err := SniffEncrypted(flow("u", net.TCPDestination(net.ParseAddress("203.0.113.88"), 443)), handshake); err == nil {
		t.Fatal("expected a marked user's encrypted flow to a well-known port to pass")
	}
	if _, err := SniffEncrypted(flow("other", peer), handshake); err == nil {
		t.Fatal("expected another user's encrypted flow to pass")
	}

	// a cached peer of a marked user is reported as a cache hit
	cachedPeer := net.UDPDestination(net.ParseAddress("203.0.113.89"), 40000)
	RememberPeer(flow("u", cachedPeer), &SniffHeader{})
	if h, err := SniffEncrypted(flow("u", net.TCPDestination(cachedPeer.Address, cachedPeer.Port)), handshake); err != nil || h.Protocol() != "bittorrent-cache" {
		t.Fatalf("expected bittorrent-cache, got %v, %v", h, err)
	}

	// flows that cannot be attributed to a user never mark anyone
	RememberPeer(flow("", peer), &SniffHeader{})
	if _, err := SniffEncrypted(flow("", net.TCPDestination(net.ParseAddress("203.0.113.90"), 40000)), handshake); err == nil {
		t.Fatal("expected an unattributed flow not to be marked")
	}
}

func TestSniffHTTPStrength(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]string
		weak  bool
	}{
		{"announce", map[string]string{":path": "/announce?info_hash=%aa&peer_id=-qB4650-x&port=1", ":bittorrent": "t.example"}, false},
		{"scrape", map[string]string{":path": "/scrape?info_hash=%aa", ":bittorrent": "t.example"}, true},
		{"user agent", map[string]string{":path": "/", "user-agent": "qBittorrent/4.6.5", ":bittorrent": "no_host"}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := session.ContextWithContent(context.Background(), &session.Content{Attributes: c.attrs})
			h, err := SniffHTTP(ctx)
			if err != nil || h.weak != c.weak {
				t.Fatalf("expected weak=%v, got %v, %v", c.weak, h, err)
			}
		})
	}
}
