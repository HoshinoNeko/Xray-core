package hysteria

import (
	"bytes"
	"io"
	"testing"
)

func TestInterConnDoesNotSilentlyTruncate(t *testing.T) {
	conn := &InterConn{ch: make(chan []byte, 2)}
	payload := bytes.Repeat([]byte{42}, 1393)
	conn.ch <- payload
	if n, err := conn.Read(make([]byte, 1200)); n != 0 || err != io.ErrShortBuffer {
		t.Fatalf("Read = %d, %v; want explicit short-buffer error", n, err)
	}
	conn.ch <- payload
	got := make([]byte, 65535)
	n, err := conn.Read(got)
	if err != nil || !bytes.Equal(got[:n], payload) {
		t.Fatalf("full-size Read = %d, %v", n, err)
	}
}
