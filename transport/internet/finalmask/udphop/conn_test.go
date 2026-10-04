package udphop

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestRemoteOnlyReceivesOnOriginalSocket(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		packet := make([]byte, 8192)
		n, addr, err := server.ReadFrom(packet)
		if err == nil {
			server.WriteTo(packet[:n], addr)
		}
	}()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Bound the underlying socket read even if the wrapper regresses.
	raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	port := server.LocalAddr().(*net.UDPAddr).Port
	conn, err := NewUDPHopConn(&Config{Remote: true, IntervalMin: 5, IntervalMax: 5, RemotePorts: []uint32{uint32(port)}}, raw)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte{37}, 4096)
	if _, err := conn.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 8192)
	n, _, err := conn.ReadFrom(got)
	if err != nil || !bytes.Equal(got[:n], payload) {
		t.Fatalf("remote-only response = %d bytes, %v", n, err)
	}
}
