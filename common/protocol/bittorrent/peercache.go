package bittorrent

import (
	"context"
	"math"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

// Recognition of encrypted BitTorrent, which no signature can see:
//   - peer cache: ip:port of flows a user sniffed as bittorrent, so the same user falling back
//     from uTP/DHT to encrypted TCP towards that peer is still recognized;
//   - user marks: a user caught with strong evidence is marked, and while marked their
//     MSE/PE shaped TCP to new peers is recognized too.
const (
	peerCacheTTL        = 10 * time.Minute
	peerCacheMax        = 65536
	peerCacheFullSweep  = time.Minute      // how often a full cache may be swept for expired entries
	peerCacheUserBudget = 2000             // new entries per user per peerCacheTTL, bounds memory per user
	userMarkTTL         = time.Hour        // how long a user caught with bittorrent stays marked
	userMarkRefresh     = time.Minute      // a mark renewed more recently than this is not rewritten
	weakEvidenceWindow  = 10 * time.Second // two weak hits to different targets within it count as strong
	sharedKeyIPs        = 8                // a key online from more client IPs is shared by several people
)

// Not peers: shared address space (CGNAT), benchmarking (default fake DNS pool), IETF protocol assignments, reserved
var nonPeerPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// markSkip matches users never marked: accounts carrying other people's traffic (bridges, chains, service keys).
// Set with XRAY_BT_MARK_SKIP, a regexp over emails (or client IPs of anonymous inbounds).
var markSkip = sync.OnceValue(func() *regexp.Regexp {
	return parseMarkSkip(platform.NewEnvFlag("xray.bt.mark.skip").GetValue(func() string { return "" }))
})

func parseMarkSkip(s string) *regexp.Regexp {
	if s == "" {
		return nil
	}
	re, err := regexp.Compile(s)
	if err != nil {
		errors.LogError(context.Background(), "invalid XRAY_BT_MARK_SKIP, no user will be marked: ", err)
		return regexp.MustCompile("") // fail safe: matches everyone
	}
	return re
}

// EncryptedHeader is the result of SniffEncrypted. Its zero value is a peer cache hit.
type EncryptedHeader struct {
	mse bool
}

func (h *EncryptedHeader) Protocol() string {
	if h.mse {
		return "bittorrent-mse"
	}
	return "bittorrent-cache"
}

func (h *EncryptedHeader) Domain() string {
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

type weakHit struct {
	target string
	at     time.Time
}

type peerCache struct {
	sync.RWMutex
	peers     map[peerKey]time.Time // expiry, extended only by fresh evidence
	budgets   map[string]*userBudget
	users     map[string]time.Time // mark expiry of users caught with bittorrent
	weak      map[string]weakHit   // last weak evidence of not yet marked users
	lastSweep time.Time
}

func newPeerCache() *peerCache {
	return &peerCache{
		peers:   make(map[peerKey]time.Time),
		budgets: make(map[string]*userBudget),
		users:   make(map[string]time.Time),
		weak:    make(map[string]weakHit),
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
	for u, w := range c.weak {
		if now.Sub(w.at) > weakEvidenceWindow {
			delete(c.weak, u)
		}
	}
}

// evidence marks the user on strong evidence, or on weak evidence towards two targets within weakEvidenceWindow
func (c *peerCache) evidence(user, target string, weak bool, now time.Time) {
	c.RLock()
	exp := c.users[user]
	c.RUnlock()
	if exp.Sub(now) > userMarkTTL-userMarkRefresh {
		return
	}

	c.Lock()
	defer c.Unlock()

	if now.Sub(c.lastSweep) > peerCacheTTL {
		c.sweep(now)
	}
	if weak {
		prev, found := c.weak[user]
		c.weak[user] = weakHit{target: target, at: now}
		if !found || prev.target == target || now.Sub(prev.at) > weakEvidenceWindow {
			return
		}
	}
	delete(c.weak, user)
	c.users[user] = now.Add(userMarkTTL)
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

// lookup reports whether the peer is cached for its user and whether the user is marked
func (c *peerCache) lookup(k peerKey, now time.Time) (cached, marked bool) {
	c.RLock()
	defer c.RUnlock()

	exp, found := c.peers[k]
	mark, markFound := c.users[k.user]
	return found && !now.After(exp), markFound && !now.After(mark)
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

func targetFromContext(ctx context.Context) net.Destination {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return net.Destination{}
	}
	return outbounds[len(outbounds)-1].Target
}

// peerFromContext returns the flow's user and destination peer, if the destination can be a peer
func peerFromContext(ctx context.Context) (peerKey, bool) {
	dest := targetFromContext(ctx)
	if !dest.IsValid() || !dest.Address.Family().IsIP() || !cacheablePort(uint16(dest.Port)) {
		return peerKey{}, false
	}
	addr, ok := netip.AddrFromSlice(dest.Address.IP())
	if !ok || !cacheableAddr(addr) {
		return peerKey{}, false
	}
	return peerKey{user: userFromContext(ctx), peer: netip.AddrPortFrom(addr, uint16(dest.Port))}, true
}

// sharedKey reports whether the user's key is online from more client IPs than one person uses.
// It relies on the "statsUserOnline" policy; without it no key is considered shared.
func sharedKey(ctx context.Context, user string) bool {
	instance := core.FromContext(ctx)
	if instance == nil {
		return false
	}
	sm, _ := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if sm == nil {
		return false
	}
	om := sm.GetOnlineMap("user>>>" + user + ">>>online")
	return om != nil && om.Count() > sharedKeyIPs
}

// RememberPeer records a flow sniffed as bittorrent: caches its destination and counts it as evidence against its user
func RememberPeer(ctx context.Context, h *SniffHeader) {
	now := time.Now()
	if user := userFromContext(ctx); user != "" && (markSkip() == nil || !markSkip().MatchString(user)) {
		peers.evidence(user, targetFromContext(ctx).String(), h.weak, now)
	}
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
		if c == 0 {
			zeros++
			if zeros > 7 {
				return false
			}
		} else {
			zeros = 0
		}
	}
	// random bytes cover about 256*(1-(255/256)^n) distinct values
	return float64(distinct) >= 0.8*256*(1-math.Pow(255.0/256, float64(len(b))))
}

// SniffEncrypted recognizes a TCP flow of unknown content as bittorrent when it goes to a peer its user
// recently talked bittorrent to, or when the user is marked and the flow is MSE/PE shaped.
// MSE shape alone is no evidence (Shadowsocks, obfs4 and the like look the same), so it never marks anyone,
// and it is not applied to shared keys.
func SniffEncrypted(ctx context.Context, b []byte) (*EncryptedHeader, error) {
	k, ok := peerFromContext(ctx)
	if !ok {
		return nil, errNotBittorrent
	}
	cached, marked := peers.lookup(k, time.Now())
	switch {
	case cached:
		return &EncryptedHeader{}, nil
	case !marked || sharedKey(ctx, k.user):
		return nil, errNotBittorrent
	case len(b) < 96:
		return nil, common.ErrNoClue // the first flight may still be arriving
	case mseShaped(b):
		return &EncryptedHeader{mse: true}, nil
	}
	return nil, errNotBittorrent
}
