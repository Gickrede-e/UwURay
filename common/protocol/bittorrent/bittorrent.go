package bittorrent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/session"
)

type SniffHeader struct {
	host string
	// weak evidence (a lone uTP SYN, an HTTP request matched by User-Agent or LSD) is not enough to mark a user
	weak bool
}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return h.host
}

var errNotBittorrent = errors.New("not bittorrent header")

var bittorrentHandshakePrefix = []byte("\x13BitTorrent protocol")

func SniffBitTorrent(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		if bytes.HasPrefix(bittorrentHandshakePrefix, b) {
			return nil, common.ErrNoClue
		}
		return nil, errNotBittorrent
	}

	if bytes.HasPrefix(b, bittorrentHandshakePrefix) {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

func SniffUDP(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	sh, err := sniffUTP(b)
	if err == nil {
		return sh, nil
	}

	sh, err = sniffUDPTracker(b)
	if err == nil {
		return sh, nil
	}

	sh, err = sniffDHT(b)
	if err == nil {
		return sh, nil
	}

	return nil, errNotBittorrent
}

func sniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, errNotBittorrent
	}

	// type 4 (ST_SYN), version 1
	if b[0] != 0x41 {
		return nil, errNotBittorrent
	}

	// timestamp_difference is always 0 in new connections
	if binary.BigEndian.Uint32(b[8:12]) != 0 {
		return nil, errNotBittorrent
	}

	// ack_nr is always 0 in ST_SYN; otherwise a 20-byte DNS query with id 0x4100 matches
	if binary.BigEndian.Uint16(b[18:20]) != 0 {
		return nil, errNotBittorrent
	}

	// TURN ChannelData (channel 0x4100-0x41FF) carries its payload length right after the channel number,
	// optionally padded to a multiple of 4 (RFC 8656 section 12.5)
	if padding := len(b) - 4 - int(binary.BigEndian.Uint16(b[2:4])); padding >= 0 && padding < 4 {
		return nil, errNotBittorrent
	}

	// Walk the extension chain. Selective ack (1) and extension bits (2)
	extension, offset := b[1], 20
	for extension != 0 {
		if len(b) < offset+2 {
			return nil, errNotBittorrent
		}
		length := int(b[offset+1])
		switch extension {
		case 1: // selective ack
			if length < 4 || length%4 != 0 {
				return nil, errNotBittorrent
			}
		case 2: // extension bits: fixed 8 bytes, sent in ST_SYN by µTorrent
			if length != 8 {
				return nil, errNotBittorrent
			}
		default:
			return nil, errNotBittorrent
		}
		if len(b) < offset+2+length {
			return nil, errNotBittorrent
		}
		extension = b[offset]
		offset += 2 + length
	}

	// extensions should consume all ST_SYN payload,
	// unless a DHT or UDP tracker packet follows in the same read
	if len(b) != offset {
		if _, err := sniffUDPTracker(b[offset:]); err == nil {
			return &SniffHeader{}, nil
		}
		return sniffDHT(b[offset:])
	}

	return &SniffHeader{weak: true}, nil
}

func sniffUDPTracker(b []byte) (*SniffHeader, error) {
	if len(b) < 16 {
		return nil, errNotBittorrent
	}

	// protocol_id
	if binary.BigEndian.Uint64(b[0:8]) != 0x41727101980 {
		return nil, errNotBittorrent
	}

	// action connect
	if binary.BigEndian.Uint32(b[8:12]) != 0 {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}

// KRPC message: bencoded dict prefix, node id (absent in errors) and message type
var dhtMessages = []struct {
	prefix, id, y []byte
}{
	{[]byte("d1:ad"), []byte("2:id20:"), []byte("1:y1:q")}, // query
	{[]byte("d1:rd"), []byte("2:id20:"), []byte("1:y1:r")}, // response
	{[]byte("d2:ip"), []byte("2:id20:"), []byte("1:y1:r")}, // BEP-42 response
	{[]byte("d1:el"), nil, []byte("1:y1:e")},               // error
}

func sniffDHT(b []byte) (*SniffHeader, error) {
	for _, m := range dhtMessages {
		if !bytes.HasPrefix(b, m.prefix) {
			continue
		}
		// query and response carry at least a 20-byte node id and a transaction id
		if m.id != nil && (len(b) < 40 || !bytes.Contains(b, m.id)) {
			return nil, errNotBittorrent
		}
		if !bytes.Contains(b, m.y) {
			return nil, errNotBittorrent
		}
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

func SniffHTTP(c context.Context) (*SniffHeader, error) {
	content := session.ContentFromContext(c)

	if content == nil || len(content.Attributes) == 0 {
		return nil, common.ErrNoClue
	}

	h, found := content.Attributes[":bittorrent"]
	if found {
		// only a tracker announce (info_hash with peer_id) is strong; scrape, HTTP seeds, LSD and User-Agent matches are weak
		path := strings.ToLower(content.Attributes[":path"])
		weak := !strings.Contains(path, "info_hash=") || !strings.Contains(path, "peer_id=")
		if h == "no_host" {
			return &SniffHeader{weak: weak}, nil
		}
		return &SniffHeader{host: h, weak: weak}, nil
	}

	return nil, errNotBittorrent
}

var clientsUA = []string{
	"libtorrent",
	"libretorrent",
	"bitcomet",
	"utorrent",
	"btwebclient",
	"azureus",
	"biglybt",
	"tixati",
	"rtorrent",
	"transmission",
	"deluge",
	"ktorrent",
	"vuze",
	"frostwire",
	"shareaza",
	"bitlord",
	"bitspirit",
	"halite",
	"bittornado",
	"bitflu",
	"mldonkey",
	"monotorrent",
	"picotorrent",
	"torrentflux",
	"tribler",
	"webtorrent",
	"btqueue",
	"bitrocket",
	"xtorrent",
	"bitwombat",
	"baretorrent",
	"arctic torrent",
	"bitbuddy",
	"bitblinder",
	"bitpump",
	"bigup",
	"ctorrent",
	"filecroc",
	"firetorrent",
	"gstorrent",
	"hekate",
	"hydranode",
	"koinonein",
	"leechcraft",
	"lh-abc",
	"linkage",
	"lphant",
	"limewire",
	"moopolice",
	"oneswarm",
	"osprey",
	"phoenix torrent",
	"reztorrent",
	"retriever",
	"swarmscope",
	"swiftbit",
	"symtorrent",
	"torrentstorm",
	"tuotu",
	"uleecher",
	"xantorrent",
	"xswifter",
	"ziptorrent",
	"xunlei",
	"qqdownload",
	"vagaa",
	"xfplay",
	"qvod",
	"mediaget",
	"zona",
	"torrserver",
	"atorrent",
	"ttorrent",
	"flud",
	"torrdroid",
	"transdroid",
	"bitlet",
	"parse-torrent",
	"node-torrent",
	"torrent-stream",
	"peerflix",
}

func IsHTTP(attrs map[string]string) bool {
	ua := strings.ToLower(attrs["user-agent"])
	for _, cua := range clientsUA {
		if strings.Contains(ua, cua) {
			return true
		}
	}

	method := attrs[":method"]
	path := strings.ToLower(attrs[":path"])

	// HTTP tracker & HTTP Seed
	if method == "GET" && strings.Contains(path, "info_hash=") {
		return true
	}

	// LSD
	if method == "BT-SEARCH" {
		return true
	}

	return false
}
