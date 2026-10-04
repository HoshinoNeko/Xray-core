package cnc

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type packetRecorder struct{ packets [][]byte }

func (w *packetRecorder) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		w.packets = append(w.packets, bytes.Clone(b.Bytes()))
	}
	return nil
}

func TestUDPWritePreservesDatagram(t *testing.T) {
	writer := &packetRecorder{}
	conn := NewConnection(ConnectionInputMultiUDP(writer))
	payload := bytes.Repeat([]byte{17}, 16000)
	n, err := conn.Write(payload)
	if err != nil || n != len(payload) || len(writer.packets) != 1 || !bytes.Equal(writer.packets[0], payload) {
		t.Fatalf("Write split or changed datagram: bytes=%d, packets=%d, err=%v", n, len(writer.packets), err)
	}
}
