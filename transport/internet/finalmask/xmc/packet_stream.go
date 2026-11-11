package xmc

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	configurationClientboundCustomPayload = 0x01
	configurationServerboundCustomPayload = 0x02
	configurationKeepAlive                = 0x04

	packetChannel = "xmc:data"
	maxPacketData = 24 * 1024
)

// keepAlivePeriod is a var so tests can shorten it.
var keepAlivePeriod = 15 * time.Second

// packetStream carries the raw proxy byte stream in Minecraft configuration
// custom payload packets. The configuration state provides bidirectional
// payload packets and keep-alives without requiring version-specific world data.
type packetStream struct {
	reader   io.Reader
	writer   io.Writer
	isClient bool

	readMu  sync.Mutex
	writeMu sync.Mutex
	pending []byte

	keepAliveID      atomic.Int64
	keepAliveReplies chan Long
	lastDataWriteNs  atomic.Int64
	done             chan struct{}
	stopOnce         sync.Once
}

func newPacketStream(reader io.Reader, writer io.Writer, isClient bool) *packetStream {
	s := &packetStream{
		reader:   reader,
		writer:   writer,
		isClient: isClient,
		done:     make(chan struct{}),
	}
	if isClient {
		s.keepAliveReplies = make(chan Long, 1)
		go s.keepAliveReplyLoop()
	} else {
		go s.keepAliveLoop(keepAlivePeriod)
	}
	return s
}

func (s *packetStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}

	for {
		packet, err := readPacket(s.reader)
		if err != nil {
			return 0, fmt.Errorf("read minecraft packet stream: %w", err)
		}

		if packet.packetID == s.remoteCustomPayloadID() {
			payload, ok, err := parseCustomPayload(packet)
			if err != nil {
				return 0, err
			}
			if !ok || len(payload) == 0 {
				continue
			}

			n := copy(p, payload)
			if n < len(payload) {
				s.pending = append(s.pending[:0], payload[n:]...)
			}
			return n, nil
		}

		if packet.packetID == configurationKeepAlive {
			var id Long
			if err := packet.readFields(&id); err != nil {
				return 0, fmt.Errorf("read minecraft keep-alive: %w", err)
			}
			if s.isClient {
				// Never block Read on the write lock: with mux, a stalled upload holding it
				// would stop downloads and deadlock both directions. One queued reply is enough.
				select {
				case s.keepAliveReplies <- id:
				default:
				}
			}
		}
	}
}

func (s *packetStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	written := 0
	for written < len(p) {
		end := written + maxPacketData
		if end > len(p) {
			end = len(p)
		}
		channel := String(packetChannel)
		payload := RestBytes(p[written:end])
		if err := writePacket(s.writer, s.localCustomPayloadID(), &channel, &payload); err != nil {
			return written, fmt.Errorf("write minecraft custom payload: %w", err)
		}
		written = end
	}
	s.lastDataWriteNs.Store(time.Now().UnixNano())

	return written, nil
}

func (s *packetStream) Stop() {
	s.stopOnce.Do(func() { close(s.done) })
}

func (s *packetStream) localCustomPayloadID() int {
	if s.isClient {
		return configurationServerboundCustomPayload
	}
	return configurationClientboundCustomPayload
}

func (s *packetStream) remoteCustomPayloadID() int {
	if s.isClient {
		return configurationClientboundCustomPayload
	}
	return configurationServerboundCustomPayload
}

func parseCustomPayload(packet *mcPacket) ([]byte, bool, error) {
	r := bytes.NewReader(packet.data)
	var channel String
	if err := channel.readFrom(r); err != nil {
		return nil, false, fmt.Errorf("read minecraft custom payload channel: %w", err)
	}
	if string(channel) != packetChannel {
		return nil, false, nil
	}
	payload := make([]byte, r.Len())
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, false, fmt.Errorf("read minecraft custom payload data: %w", err)
	}
	return payload, true, nil
}

func (s *packetStream) writeKeepAlive(id Long) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := writePacket(s.writer, configurationKeepAlive, &id); err != nil {
		return fmt.Errorf("write minecraft keep-alive: %w", err)
	}
	return nil
}

func (s *packetStream) keepAliveReplyLoop() {
	for {
		select {
		case id := <-s.keepAliveReplies:
			if err := s.writeKeepAlive(id); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *packetStream) keepAliveLoop(period time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// Stock clients answer keep-alives from Read under the write lock, which deadlocks
			// when they upload while we download (mux). Only ping when we have not sent data lately.
			if time.Since(time.Unix(0, s.lastDataWriteNs.Load())) < period {
				continue
			}
			id := Long(s.keepAliveID.Add(1))
			if err := s.writeKeepAlive(id); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}
