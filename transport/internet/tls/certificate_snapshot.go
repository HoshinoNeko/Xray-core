package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/ocsp"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"google.golang.org/protobuf/proto"
)

// Only the reload goroutine owns entry. Published certificates (including their
// backing byte slices) must never be modified after Store: TLS may retain them
// after GetCertificate returns.
type certificateSnapshot struct {
	entry   *Certificate
	current atomic.Pointer[tls.Certificate]
}

func parseKeyPair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	return &pair, err
}

func newCertificateSnapshot(entry *Certificate) (*certificateSnapshot, error) {
	// Multiple TLS configurations may be built from the same protobuf config.
	// Do not let any reload worker mutate that shared source configuration.
	entry = proto.Clone(entry).(*Certificate)
	pair, err := parseKeyPair(entry.Certificate, entry.Key)
	if err != nil {
		return nil, err
	}
	s := &certificateSnapshot{entry: entry}
	s.current.Store(pair)
	return s, nil
}

// refresh is called by exactly one worker. File/parse failures leave both the
// published snapshot and the last accepted PEM unchanged, allowing retries.
func (s *certificateSnapshot) refresh(fetchOCSP func([][]byte) ([]byte, error)) error {
	entry := s.entry
	current := s.current.Load()
	next := current
	if entry.CertificatePath != "" && entry.KeyPath != "" {
		certPEM, err := filesystem.ReadCert(entry.CertificatePath)
		if err != nil {
			return err
		}
		keyPEM, err := filesystem.ReadCert(entry.KeyPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(certPEM, entry.Certificate) || !bytes.Equal(keyPEM, entry.Key) {
			next, err = parseKeyPair(certPEM, keyPEM)
			if err != nil {
				return err
			}
			entry.Certificate, entry.Key = certPEM, keyPEM
		}
	}
	var ocspErr error
	if entry.OcspStapling != 0 {
		var staple []byte
		staple, ocspErr = fetchOCSP(next.Certificate)
		if ocspErr == nil && !bytes.Equal(staple, next.OCSPStaple) {
			updated := *next
			updated.OCSPStaple = bytes.Clone(staple)
			next = &updated
		}
	}
	if next != current {
		s.current.Store(next)
	}
	return ocspErr
}

func (s *certificateSnapshot) watch(stop <-chan struct{}) {
	if s.entry.OneTimeLoading {
		return
	}
	interval := uint64(3600)
	if s.entry.OcspStapling != 0 {
		interval = s.entry.OcspStapling
	}
	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			if err := s.refresh(ocsp.GetOCSPForCert); err != nil {
				errors.LogWarningInner(context.Background(), err, "certificate/OCSP refresh failed; retrying next interval")
			}
			select {
			case <-ticker.C:
			case <-stop:
				return
			}
		}
	}()
}

type certificateStore struct {
	slots []*certificateSnapshot
}

func (s *certificateStore) load() []*tls.Certificate {
	certs := make([]*tls.Certificate, len(s.slots))
	for i, slot := range s.slots {
		certs[i] = slot.current.Load()
	}
	return certs
}

func (c *Config) buildCertificateLoader() (func() []*tls.Certificate, func()) {
	stop := make(chan struct{})
	stopOnce := sync.OnceFunc(func() { close(stop) })
	slots := make([]*certificateSnapshot, 0, len(c.Certificate))
	for _, entry := range c.Certificate {
		if entry.Usage != Certificate_ENCIPHERMENT {
			continue
		}
		slot, err := newCertificateSnapshot(entry)
		if err != nil {
			errors.LogWarningInner(context.Background(), err, "ignoring invalid X509 key pair")
			continue
		}
		slots = append(slots, slot)
		slot.watch(stop)
	}
	// slots is immutable after construction. Each handshake receives a private
	// slice, and each certificate pointer is obtained with an atomic load.
	store := &certificateStore{slots: slots}
	// Bind lifetime to the shared loader, not a single tls.Config: Clone retains
	// GetCertificate and must continue receiving updates after the original dies.
	runtime.AddCleanup(store, func(stop func()) { stop() }, stopOnce)
	return store.load, stopOnce
}
