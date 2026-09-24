package tls

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func snapshotTestCert(t *testing.T, name string) *Certificate {
	t.Helper()
	c, err := cert.Generate(nil, cert.CommonName(name), cert.DNSNames(name))
	if err != nil {
		t.Fatal(err)
	}
	return ParseCertificate(c)
}

func TestCertificateSnapshotConcurrentOCSP(t *testing.T) {
	entry := snapshotTestCert(t, "localhost")
	entry.OcspStapling = 1
	slot, err := newCertificateSnapshot(entry)
	if err != nil {
		t.Fatal(err)
	}
	old := slot.current.Load()
	get := getNewGetCertificateFunc(func() []*gotls.Certificate {
		return []*gotls.Certificate{slot.current.Load()}
	}, true)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				c, err := get(&gotls.ClientHelloInfo{ServerName: "localhost"})
				if err != nil {
					t.Error(err)
					return
				}
				// Retain and read after returning from GetCertificate, as TLS does.
				before := bytes.Clone(c.OCSPStaple)
				time.Sleep(time.Microsecond)
				if !bytes.Equal(before, c.OCSPStaple) || c.Leaf.DNSNames[0] != "localhost" {
					t.Error("published certificate mutated")
				}
			}
		})
	}
	for i := range 1000 {
		data := []byte{byte(i), byte(i >> 8)}
		if err := slot.refresh(func([][]byte) ([]byte, error) { return data, nil }); err != nil {
			t.Fatal(err)
		}
		data[0] = 0 // The fetched buffer is not owned by the published snapshot.
	}
	wg.Wait()
	if len(old.OCSPStaple) != 0 || slot.current.Load() == old {
		t.Fatal("OCSP update did not create a new immutable certificate")
	}
	before := slot.current.Load()
	if err := slot.refresh(func([][]byte) ([]byte, error) { return nil, errors.New("temporary OCSP failure") }); err == nil || slot.current.Load() != before {
		t.Fatal("OCSP failure replaced last valid certificate")
	}
}

func TestCertificateSnapshotReloadRecovery(t *testing.T) {
	entry := snapshotTestCert(t, "old.example")
	renewed := snapshotTestCert(t, "new.example")
	dir := t.TempDir()
	entry.CertificatePath = filepath.Join(dir, "cert.pem")
	entry.KeyPath = filepath.Join(dir, "key.pem")
	slot, err := newCertificateSnapshot(entry)
	if err != nil {
		t.Fatal(err)
	}
	old := slot.current.Load()
	noOCSP := func([][]byte) ([]byte, error) { t.Fatal("unexpected OCSP fetch"); return nil, nil }
	if err := slot.refresh(noOCSP); err == nil || slot.current.Load() != old {
		t.Fatal("missing files did not preserve old certificate")
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(entry.CertificatePath, renewed.Certificate)
	write(entry.KeyPath, entry.Key) // Renewal files may be replaced separately.
	if err := slot.refresh(noOCSP); err == nil || slot.current.Load() != old {
		t.Fatal("mismatched key pair replaced old certificate")
	}
	write(entry.KeyPath, renewed.Key)
	if err := slot.refresh(noOCSP); err != nil {
		t.Fatal(err)
	}
	if slot.current.Load().Leaf.DNSNames[0] != "new.example" || old.Leaf.DNSNames[0] != "old.example" {
		t.Fatal("renewal failed or old certificate mutated")
	}
	if bytes.Equal(entry.Certificate, renewed.Certificate) {
		t.Fatal("shared source config mutated")
	}
}

func TestCertificateSnapshotSNIAndOneTimeLoading(t *testing.T) {
	entry := snapshotTestCert(t, "*.example.com")
	entry.OneTimeLoading = true
	entry.OcspStapling = 1
	dir := t.TempDir()
	entry.CertificatePath = filepath.Join(dir, "cert.pem")
	entry.KeyPath = filepath.Join(dir, "key.pem")
	renewed := snapshotTestCert(t, "renewed.example.com")
	if err := os.WriteFile(entry.CertificatePath, renewed.Certificate, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry.KeyPath, renewed.Key, 0600); err != nil {
		t.Fatal(err)
	}
	config := (&Config{Certificate: []*Certificate{entry}, RejectUnknownSni: true}).GetTLSConfig()
	first, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: "WWW.EXAMPLE.COM"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: "unknown.test"}); err == nil {
		t.Fatal("unknown SNI accepted")
	}
	time.Sleep(1100 * time.Millisecond)
	last, err := config.GetCertificate(&gotls.ClientHelloInfo{ServerName: "www.example.com"})
	if err != nil || first != last {
		t.Fatal("OneTimeLoading changed certificate")
	}
}

func TestCertificateSnapshotWatcherHandshakeRecovery(t *testing.T) {
	entry := snapshotTestCert(t, "old.example")
	renewed := snapshotTestCert(t, "new.example")
	dir := t.TempDir()
	entry.CertificatePath = filepath.Join(dir, "cert.pem")
	entry.KeyPath = filepath.Join(dir, "key.pem")
	entry.OcspStapling = 1
	load, stop := (&Config{Certificate: []*Certificate{entry}}).buildCertificateLoader()
	defer stop()
	config := &gotls.Config{GetCertificate: getNewGetCertificateFunc(load, false)}
	handshake := func() string {
		t.Helper()
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server := gotls.Server(a, config)
		// This test inspects the presented certificate, not trust validation.
		client := gotls.Client(b, &gotls.Config{InsecureSkipVerify: true})
		done := make(chan error, 1)
		go func() { done <- server.HandshakeContext(ctx) }()
		if err := client.HandshakeContext(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		return client.ConnectionState().PeerCertificates[0].DNSNames[0]
	}
	if handshake() != "old.example" {
		t.Fatal("initial certificate missing")
	}
	// Allow the worker to encounter missing files before installing the renewal.
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(entry.CertificatePath, renewed.Certificate, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry.KeyPath, renewed.Key, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if handshake() == "new.example" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("certificate watcher did not recover after missing files")
}
