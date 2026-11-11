package xmc

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPacketStreamUsesPlainFraming(t *testing.T) {
	payload := []byte("hello")
	var wire bytes.Buffer
	stream := newPacketStream(bytes.NewReader(nil), &wire, true)

	written, err := stream.Write(payload)
	if err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if written != len(payload) {
		t.Fatalf("written = %d, want %d", written, len(payload))
	}
	wantOutbound := []byte{0x0f, 0x02, 0x08, 'x', 'm', 'c', ':', 'd', 'a', 't', 'a', 'h', 'e', 'l', 'l', 'o'}
	if !bytes.Equal(wire.Bytes(), wantOutbound) {
		t.Fatalf("wire frame = %x, want %x", wire.Bytes(), wantOutbound)
	}

	wantInbound := append([]byte(nil), wantOutbound...)
	wantInbound[1] = configurationClientboundCustomPayload
	reader := newPacketStream(bytes.NewReader(wantInbound), io.Discard, true)
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(reader, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestPacketStreamRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const password = "packet-stream-shared-key"
	privateKey, publicKey := deriveTestRSAKey(t, password)
	profiles := []loginProfile{testLoginProfile("packet_user")}
	clientPayload := bytes.Repeat([]byte("client-payload-"), 5000)
	serverPayload := bytes.Repeat([]byte("server-payload-"), 5000)
	serverDone := make(chan error, 1)

	go func() {
		rawConn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer rawConn.Close()

		server, wrapErr := wrapConnServer(rawConn, profiles, password, privateKey, publicKey)
		if wrapErr != nil {
			serverDone <- wrapErr
			return
		}
		got := make([]byte, len(clientPayload))
		if _, readErr := io.ReadFull(server, got); readErr != nil {
			serverDone <- readErr
			return
		}
		if !bytes.Equal(got, clientPayload) {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, writeErr := server.Write(serverPayload)
		serverDone <- writeErr
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawClient.Close()

	client, err := newClientConn(rawClient, profiles, password, publicKey, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write(clientPayload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(serverPayload))
	if _, err = io.ReadFull(client, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, serverPayload) {
		t.Fatal("server payload mismatch")
	}
	if err = <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// Mux uploads and downloads on one connection while the server echoes, so a client
// keep-alive reply that waits behind a blocked upload would stall both directions.
func TestPacketStreamKeepAliveDoesNotDeadlockFullDuplex(t *testing.T) {
	previousPeriod := keepAlivePeriod
	keepAlivePeriod = 5 * time.Millisecond
	defer func() { keepAlivePeriod = previousPeriod }()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client := newPacketStream(clientConn, clientConn, true)
	server := newPacketStream(serverConn, serverConn, false)
	defer server.Stop()
	const totalLength = 4 * 1024 * 1024
	go func() {
		buffer := make([]byte, 32*1024)
		for {
			n, err := server.Read(buffer)
			if err != nil {
				return
			}
			if _, err = server.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()
	go func() {
		chunk := bytes.Repeat([]byte{0x5a}, 32*1024)
		for written := 0; written < totalLength; written += len(chunk) {
			if _, err := client.Write(chunk); err != nil {
				return
			}
		}
	}()

	readDone := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, client, totalLength)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("full-duplex stream deadlocked")
	}
}

// Stock clients (before the async reply fix) answer keep-alives from their read loop under
// the write lock. The server must not ping mid-transfer, or a mux connection deadlocks.
func TestServerKeepAliveDoesNotDeadlockStockClient(t *testing.T) {
	previousPeriod := keepAlivePeriod
	keepAlivePeriod = 5 * time.Millisecond
	defer func() { keepAlivePeriod = previousPeriod }()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	server := newPacketStream(serverConn, serverConn, false)
	defer server.Stop()
	var clientWriteMu sync.Mutex
	const totalLength = 4 * 1024 * 1024
	go func() {
		buffer := make([]byte, 32*1024)
		for {
			n, err := server.Read(buffer)
			if err != nil {
				return
			}
			if _, err = server.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()
	go func() {
		chunk := bytes.Repeat([]byte{0x5a}, 24*1024)
		for written := 0; written < totalLength; written += len(chunk) {
			channel := String(packetChannel)
			payload := RestBytes(chunk)
			clientWriteMu.Lock()
			err := writePacket(clientConn, configurationServerboundCustomPayload, &channel, &payload)
			clientWriteMu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	readDone := make(chan error, 1)
	go func() {
		received := 0
		for received < totalLength {
			packet, err := readPacket(clientConn)
			if err != nil {
				readDone <- err
				return
			}
			switch packet.packetID {
			case configurationClientboundCustomPayload:
				payload, _, err := parseCustomPayload(packet)
				if err != nil {
					readDone <- err
					return
				}
				received += len(payload)
			case configurationKeepAlive:
				var id Long
				if err = packet.readFields(&id); err != nil {
					readDone <- err
					return
				}
				clientWriteMu.Lock()
				err = writePacket(clientConn, configurationKeepAlive, &id)
				clientWriteMu.Unlock()
				if err != nil {
					readDone <- err
					return
				}
			}
		}
		readDone <- nil
	}()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stock client deadlocked against server keep-alives")
	}
}
