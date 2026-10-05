package bittorrent

import (
	"context"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/session"
)

// Peer cache remembers ip:port of flows a user sniffed as bittorrent, so the same user falling back
// from uTP/DHT to encrypted TCP towards that peer is still recognized.
// It also marks the user: their encrypted (MSE/PE shaped) TCP to new peers is then recognized too.
const (
	peerCacheTTL        = 10 * time.Minute
	peerCacheMax        = 65536
	peerCacheFullSweep  = time.Minute // how often a full cache may be swept for expired entries
	peerCacheUserBudget = 2000        // new entries per user per peerCacheTTL, bounds memory per user
	userMarkTTL         = time.Hour   // how long a user caught with bittorrent stays marked
)

// Not peers: shared address space (CGNAT), benchmarking (default fake DNS pool), IETF protocol assignments, reserved
var nonPeerPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

type PeerCacheHeader struct {
	protocol string
}

func (h *PeerCacheHeader) Protocol() string {
	return h.protocol
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
	users     map[string]time.Time // mark expiry of users caught with bittorrent
	lastSweep time.Time
}

func newPeerCache() *peerCache {
	return &peerCache{
		peers:   make(map[peerKey]time.Time),
		budgets: make(map[string]*userBudget),
		users:   make(map[string]time.Time),
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
	for u, exp := range c.users {
		if now.After(exp) {
			delete(c.users, u)
		}
	}
}

func (c *peerCache) mark(user string, now time.Time) {
	c.Lock()
	defer c.Unlock()

	c.users[user] = now.Add(userMarkTTL)
}

func (c *peerCache) marked(user string, now time.Time) bool {
	c.RLock()
	defer c.RUnlock()

	exp, found := c.users[user]
	return found && !now.After(exp)
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

// userFromContext returns the flow's user: email, or client IP for anonymous inbounds
func userFromContext(ctx context.Context) string {
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		if inbound.User != nil && inbound.User.Email != "" {
			return inbound.User.Email
		}
		if inbound.Source.IsValid() {
			return inbound.Source.Address.String()
		}
	}
	return ""
}

// peerFromContext returns the flow's user and destination peer, if the destination can be a peer
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
	return peerKey{user: userFromContext(ctx), peer: netip.AddrPortFrom(addr, uint16(dest.Port))}, true
}

// RememberPeer marks the user of a flow sniffed as bittorrent and caches its destination
func RememberPeer(ctx context.Context) {
	now := time.Now()
	peers.mark(userFromContext(ctx), now)
	if k, ok := peerFromContext(ctx); ok {
		peers.add(k, now)
	}
}

// mseShaped reports whether b looks like the first flight of an MSE/PE encrypted connection:
// a 96-byte DH public key plus 0-512 bytes of random padding, all indistinguishable from random
func mseShaped(b []byte) bool {
	if len(b) < 96 || len(b) > 608 {
		return false
	}
	var seen [256]bool
	distinct, zeros := 0, 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			distinct++
		}
		if c != 0 {
			zeros = 0
		} else if zeros++; zeros > 7 {
			return false
		}
	}
	// random bytes cover about 256*(1-(255/256)^n) distinct values
	return float64(distinct) >= 0.8*256*(1-math.Pow(255.0/256, float64(len(b))))
}

// SniffPeerCache recognizes a TCP flow of unknown content as bittorrent when it goes to a peer
// its user recently talked bittorrent to, or when the user is marked and the flow is MSE/PE shaped.
// MSE shape alone is no evidence (Shadowsocks, obfs4 and the like look the same), so it never marks anyone.
func SniffPeerCache(ctx context.Context, b []byte) (*PeerCacheHeader, error) {
	k, ok := peerFromContext(ctx)
	if !ok {
		return nil, errNotBittorrent
	}
	now := time.Now()
	if peers.has(k, now) {
		return &PeerCacheHeader{protocol: "bittorrent-cache"}, nil
	}
	if peers.marked(k.user, now) && mseShaped(b) {
		return &PeerCacheHeader{protocol: "bittorrent-mse"}, nil
	}
	return nil, errNotBittorrent
}
