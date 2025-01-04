// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type certPaths struct {
	RootCAKey  string
	RootCACert string
	TLSKey     string
	TLSCert    string
}

func TestClient_SetRootCertificateWatcher(t *testing.T) {
	// For this test, we want to:
	// - Generate root CA
	// - Generate TLS cert signed with root CA
	// - Start a Test HTTPS server
	// - Create a Resty client with SetRootCertificateWatcher and SetClientRootCertificateWatcher
	// - Send multiple requests and re-generate the certs periodically to reproduce renewal

	certDir := t.TempDir()
	paths := certPaths{
		RootCAKey:  filepath.Join(certDir, "root-ca.key"),
		RootCACert: filepath.Join(certDir, "root-ca.crt"),
		TLSKey:     filepath.Join(certDir, "tls.key"),
		TLSCert:    filepath.Join(certDir, "tls.crt"),
	}

	generateCerts(t, paths)

	ts := createTestTLSServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, paths.TLSCert, paths.TLSKey)
	defer ts.Close()

	poolingInterval := 100 * time.Millisecond

	client := NewWithTransportSettings(&TransportSettings{
		// Make sure that TLS handshake happens for all request
		// (otherwise, test may succeed because 1st TLS session is re-used)
		DisableKeepAlives: true,
	}).SetRootCertificatesWatcher(
		&CertWatcherOptions{PoolInterval: poolingInterval},
		paths.RootCACert,
	).SetClientRootCertificatesWatcher(
		&CertWatcherOptions{PoolInterval: poolingInterval},
		paths.RootCACert,
	).SetDebug(false)

	url := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	t.Log("Test URL:", url)

	t.Run("Cert Watcher should handle certs rotation", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			res, err := client.R().Get(url)
			if err != nil {
				t.Fatal(err)
			}

			assertEqual(t, res.StatusCode(), http.StatusOK)

			if i%2 == 1 {
				// Re-generate certs to simulate renewal scenario
				generateCerts(t, paths)
				time.Sleep(50 * time.Millisecond)
			}

		}
	})

	t.Run("Cert Watcher should recover on failure", func(t *testing.T) {
		// Delete root cert and re-create it to ensure that cert watcher is able to recover

		// Re-generate certs to invalidate existing cert
		generateCerts(t, paths)
		// Delete root cert so that Cert Watcher will fail
		err := os.RemoveAll(paths.RootCACert)
		assertNil(t, err)

		// Reset TLS config to ensure that previous root cert is not re-used
		tr, err := client.HTTPTransport()
		assertNil(t, err)
		tr.TLSClientConfig = nil
		client.SetTransport(tr)

		time.Sleep(50 * time.Millisecond)

		_, err = client.R().Get(url)
		// We expect an error since root cert has been deleted
		assertNotNil(t, err)

		// Re-generate certs. We except cert watcher to reload the new root cert.
		generateCerts(t, paths)
		time.Sleep(50 * time.Millisecond)
		_, err = client.R().Get(url)
		assertNil(t, err)
	})

	err := client.Close()
	assertNil(t, err)
}

func generateCerts(t *testing.T, paths certPaths) {
	rootKey, rootCert, err := generateRootCA(paths.RootCAKey, paths.RootCACert)
	if err != nil {
		t.Fatal(err)
	}

	if err := generateTLSCert(paths.TLSKey, paths.TLSCert, rootKey, rootCert); err != nil {
		t.Fatal(err)
	}
}

// Generate a Root Certificate Authority (CA)
func generateRootCA(keyPath, certPath string) (*rsa.PrivateKey, []byte, error) {
	// Generate the key for the Root CA
	rootKey, err := generateKey()
	if err != nil {
		return nil, nil, err
	}

	// Define the maximum value you want for the random big integer
	max := new(big.Int).Lsh(big.NewInt(1), 256) // Example: 256 bits

	// Generate a random big.Int
	randomBigInt, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, nil, err
	}

	// Create the root certificate template
	rootCertTemplate := &x509.Certificate{
		SerialNumber: randomBigInt,
		Subject: pkix.Name{
			Organization: []string{"YourOrg"},
			Country:      []string{"US"},
			Province:     []string{"State"},
			Locality:     []string{"City"},
			CommonName:   "YourRootCA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// Self-sign the root certificate
	rootCert, err := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	// Save the Root CA key and certificate
	if err := savePEMKey(keyPath, rootKey); err != nil {
		return nil, nil, err
	}
	if err := savePEMCert(certPath, rootCert); err != nil {
		return nil, nil, err
	}

	return rootKey, rootCert, nil
}

// Generate a TLS Certificate signed by the Root CA
func generateTLSCert(keyPath, certPath string, rootKey *rsa.PrivateKey, rootCert []byte) error {
	// Generate a key for the server
	serverKey, err := generateKey()
	if err != nil {
		return err
	}

	// Parse the Root CA certificate
	parsedRootCert, err := x509.ParseCertificate(rootCert)
	if err != nil {
		return err
	}

	// Create the server certificate template
	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"YourOrg"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 10),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	// Sign the server certificate with the Root CA
	serverCert, err := x509.CreateCertificate(rand.Reader, serverCertTemplate, parsedRootCert, &serverKey.PublicKey, rootKey)
	if err != nil {
		return err
	}

	// Save the server key and certificate
	if err := savePEMKey(keyPath, serverKey); err != nil {
		return err
	}
	if err := savePEMCert(certPath, serverCert); err != nil {
		return err
	}

	return nil
}

func generateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	keyFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.Encode(keyFile, privateKeyPEM)
}

func savePEMCert(fileName string, cert []byte) error {
	certFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer certFile.Close()

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	return pem.Encode(certFile, certPEM)
}
