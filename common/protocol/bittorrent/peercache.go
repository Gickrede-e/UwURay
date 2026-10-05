package bittorrent

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/session"
)

// Peer cache remembers ip:port of flows sniffed as bittorrent, so a client falling back
// from uTP/DHT to encrypted TCP towards the same peer is still recognized.
const (
	peerCacheTTL         = 10 * time.Minute
	peerCacheMax         = 65536
	peerCacheEmailBudget = 2000 // new entries per email per peerCacheTTL, limits cache poisoning
)

type PeerCacheHeader struct{}

func (h *PeerCacheHeader) Protocol() string {
	return "bittorrent-cache"
}

func (h *PeerCacheHeader) Domain() string {
	return ""
}

type emailBudget struct {
	used  int
	since time.Time
}

type peerCache struct {
	sync.Mutex
	peers     map[netip.AddrPort]time.Time // expiry, extended only by fresh evidence
	budgets   map[string]*emailBudget
	lastSweep time.Time
}

func newPeerCache() *peerCache {
	return &peerCache{
		peers:   make(map[netip.AddrPort]time.Time),
		budgets: make(map[string]*emailBudget),
	}
}

var peers = newPeerCache()

func (c *peerCache) add(peer netip.AddrPort, email string, now time.Time) {
	c.Lock()
	defer c.Unlock()

	if now.Sub(c.lastSweep) > peerCacheTTL {
		c.lastSweep = now
		for p, exp := range c.peers {
			if now.After(exp) {
				delete(c.peers, p)
			}
		}
		for e, b := range c.budgets {
			if now.Sub(b.since) > peerCacheTTL {
				delete(c.budgets, e)
			}
		}
	}

	if exp, found := c.peers[peer]; found && !now.After(exp) {
		c.peers[peer] = now.Add(peerCacheTTL)
		return
	}

	// ponytail: full cache drops new peers until the next sweep, LRU if it ever fills up in practice
	if len(c.peers) >= peerCacheMax {
		return
	}

	b := c.budgets[email]
	if b == nil || now.Sub(b.since) > peerCacheTTL {
		b = &emailBudget{since: now}
		c.budgets[email] = b
	}
	if b.used >= peerCacheEmailBudget {
		return
	}
	b.used++
	c.peers[peer] = now.Add(peerCacheTTL)
}

func (c *peerCache) has(peer netip.AddrPort, now time.Time) bool {
	c.Lock()
	defer c.Unlock()

	exp, found := c.peers[peer]
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

func peerFromContext(ctx context.Context) (netip.AddrPort, bool) {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return netip.AddrPort{}, false
	}
	dest := outbounds[len(outbounds)-1].Target
	if !dest.Address.Family().IsIP() || !cacheablePort(uint16(dest.Port)) {
		return netip.AddrPort{}, false
	}
	addr, ok := netip.AddrFromSlice(dest.Address.IP())
	addr = addr.Unmap()
	if !ok || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, uint16(dest.Port)), true
}

// RememberPeer caches the destination of a flow sniffed as bittorrent
func RememberPeer(ctx context.Context) {
	peer, ok := peerFromContext(ctx)
	if !ok {
		return
	}
	email := ""
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		email = inbound.User.Email
	}
	peers.add(peer, email, time.Now())
}

// SniffPeerCache recognizes a flow of unknown content towards a recently seen bittorrent peer
func SniffPeerCache(ctx context.Context) (*PeerCacheHeader, error) {
	if peer, ok := peerFromContext(ctx); ok && peers.has(peer, time.Now()) {
		return &PeerCacheHeader{}, nil
	}
	return nil, errNotBittorrent
}
