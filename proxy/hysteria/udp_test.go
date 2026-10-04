package hysteria

import (
	"bytes"
	"io"
	"strconv"
	"testing"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/buf"
)

type datagramQueue struct {
	packets [][]byte
	limit   int
}

func (q *datagramQueue) Write(p []byte) (int, error) {
	if len(p) > q.limit {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(q.limit)}
	}
	q.packets = append(q.packets, bytes.Clone(p))
	return len(p), nil
}

func (q *datagramQueue) Read(p []byte) (int, error) {
	if len(q.packets) == 0 {
		return 0, io.EOF
	}
	packet := q.packets[0]
	q.packets = q.packets[1:]
	if len(p) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, packet), nil
}

func TestUDPRoundTripLargeDatagrams(t *testing.T) {
	for _, size := range []int{11, 1200, 4096, 8192, 16000, 65507} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i*31 + i/251)
			}
			queue := &datagramQueue{limit: 1393}
			writer := &UDPWriter{writer: queue, addr: "127.0.0.1:12345"}
			packet := buf.NewWithSize(int32(size))
			copy(packet.Extend(int32(size)), payload)
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
				t.Fatal(err)
			}
			// Fragments may arrive out of order; retain every fragment's bytes.
			for i, j := 0, len(queue.packets)-1; i < j; i, j = i+1, j-1 {
				queue.packets[i], queue.packets[j] = queue.packets[j], queue.packets[i]
			}
			reader := &UDPReader{reader: queue, df: &Defragger{}}
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(mb)
			if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) {
				t.Fatalf("datagram boundary or payload changed: want %d bytes", size)
			}
			if len(queue.packets) != 0 {
				t.Fatal("unconsumed fragments")
			}
		})
	}
}

func TestUDPReaderShortBuffer(t *testing.T) {
	msg := &UDPMessage{FragCount: 1, Addr: "127.0.0.1:12345", Data: make([]byte, 4096)}
	packet := make([]byte, msg.Size())
	msg.Serialize(packet)
	reader := &UDPReader{reader: &datagramQueue{packets: [][]byte{packet}}, df: &Defragger{}}
	if _, _, err := reader.ReadFrom(make([]byte, 1200)); err != io.ErrShortBuffer {
		t.Fatalf("want explicit short-buffer error, got %v", err)
	}
}
