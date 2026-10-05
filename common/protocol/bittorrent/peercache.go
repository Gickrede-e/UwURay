package bittorrent

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/session"
)

// Peer cache remembers ip:port of flows a user sniffed as bittorrent, so the same user falling back
// from uTP/DHT to encrypted TCP towards that peer is still recognized.
const (
	peerCacheTTL         = 10 * time.Minute
	peerCacheMax         = 65536
	peerCacheFullSweep   = time.Minute // how often a full cache may be swept for expired entries
	peerCacheUserBudget  = 2000        // new entries per user per peerCacheTTL, bounds memory per user
)

// Not peers: shared address space (CGNAT), benchmarking (default fake DNS pool), IETF protocol assignments, reserved
var nonPeerPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

type PeerCacheHeader struct{}

func (h *PeerCacheHeader) Protocol() string {
	return "bittorrent-cache"
}

func (h *PeerCacheHeader) Domain() string {
	return ""
}

// peerKey scopes a peer to the user who was seen talking bittorrent to it,
// so nobody can make other users' traffic look like bittorrent
type peerKey struct {
	user string
	peer netip.AddrPort
}

type userBudget struct {
	used  int
	since time.Time
}

type peerCache struct {
	sync.RWMutex
	peers     map[peerKey]time.Time // expiry, extended only by fresh evidence
	budgets   map[string]*userBudget
	lastSweep time.Time
}

func newPeerCache() *peerCache {
	return &peerCache{
		peers:   make(map[peerKey]time.Time),
		budgets: make(map[string]*userBudget),
	}
}

var peers = newPeerCache()

func (c *peerCache) sweep(now time.Time) {
	c.lastSweep = now
	for k, exp := range c.peers {
		if now.After(exp) {
			delete(c.peers, k)
		}
	}
	for u, b := range c.budgets {
		if now.Sub(b.since) > peerCacheTTL {
			delete(c.budgets, u)
		}
	}
}

func (c *peerCache) add(k peerKey, now time.Time) {
	c.Lock()
	defer c.Unlock()

	exp, found := c.peers[k]
	if found && !now.After(exp) {
		c.peers[k] = now.Add(peerCacheTTL)
		return
	}

	full := len(c.peers) >= peerCacheMax
	if now.Sub(c.lastSweep) > peerCacheTTL || (full && now.Sub(c.lastSweep) > peerCacheFullSweep) {
		c.sweep(now)
		_, found = c.peers[k]
		full = len(c.peers) >= peerCacheMax
	}
	// a full cache still accepts an expired entry being renewed in place
	if full && !found {
		return
	}

	b := c.budgets[k.user]
	if b == nil || now.Sub(b.since) > peerCacheTTL {
		b = &userBudget{since: now}
		c.budgets[k.user] = b
	}
	if b.used >= peerCacheUserBudget {
		return
	}
	b.used++
	c.peers[k] = now.Add(peerCacheTTL)
}

func (c *peerCache) has(k peerKey, now time.Time) bool {
	c.RLock()
	defer c.RUnlock()

	exp, found := c.peers[k]
	return found && !now.After(exp)
}

// cacheablePort excludes well-known services and ports of calls, push and VoIP relays
func cacheablePort(p uint16) bool {
	switch {
	case p < 1024,
		p == 3544, p == 5246, p == 5247, p == 5349, p == 7680, p == 8080, p == 8443,
		p >= 3478 && p <= 3481,
		p >= 5222 && p <= 5228,
		p >= 8801 && p <= 8810,
		p >= 19302 && p <= 19309:
		return false
	}
	return true
}

func cacheableAddr(addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, p := range nonPeerPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// peerFromContext returns the flow's user (email, or client IP for anonymous inbounds) and destination peer
func peerFromContext(ctx context.Context) (peerKey, bool) {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return peerKey{}, false
	}
	dest := outbounds[len(outbounds)-1].Target
	if !dest.Address.Family().IsIP() || !cacheablePort(uint16(dest.Port)) {
		return peerKey{}, false
	}
	addr, ok := netip.AddrFromSlice(dest.Address.IP())
	if !ok || !cacheableAddr(addr) {
		return peerKey{}, false
	}
	user := ""
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		if inbound.User != nil && inbound.User.Email != "" {
			user = inbound.User.Email
		} else if inbound.Source.IsValid() {
			user = inbound.Source.Address.String()
		}
	}
	return peerKey{user: user, peer: netip.AddrPortFrom(addr, uint16(dest.Port))}, true
}

// RememberPeer caches the destination of a flow sniffed as bittorrent
func RememberPeer(ctx context.Context) {
	if k, ok := peerFromContext(ctx); ok {
		peers.add(k, time.Now())
	}
}

// SniffPeerCache recognizes a flow of unknown content towards a peer its user recently talked bittorrent to
func SniffPeerCache(ctx context.Context) (*PeerCacheHeader, error) {
	if k, ok := peerFromContext(ctx); ok && peers.has(k, time.Now()) {
		return &PeerCacheHeader{}, nil
	}
	return nil, errNotBittorrent
}
