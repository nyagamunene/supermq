// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package callback_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/absmach/supermq/pkg/callback"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	permission     = "test_permission"
	entityType     = "client"
	userID         = "user_id"
	domainID       = "domain_id"
	filePermission = 0o644
)

var (
	pl = map[string]interface{}{
		"entity_type": entityType,
		"sender":      userID,
		"domain":      domainID,
		"time":        time.Now().String(),
		"permission":  permission,
	}
)

func TestNewCalloutClient(t *testing.T) {
	cases := []struct {
		desc        string
		ctls        bool
		certPath    string
		keyPath     string
		caPath      string
		timeout     time.Duration
		expectError bool
	}{
		{
			desc:        "successful client creation without TLS",
			ctls:        false,
			timeout:     time.Second,
			expectError: false,
		},
		{
			desc:        "successful client creation with TLS",
			ctls:        true,
			certPath:    "client.crt",
			keyPath:     "client.key",
			caPath:      "ca.crt",
			timeout:     time.Second,
			expectError: false,
		},
		{
			desc:        "failed client creation with invalid cert",
			ctls:        true,
			certPath:    "invalid.crt",
			keyPath:     "invalid.key",
			caPath:      "invalid.ca",
			timeout:     time.Second,
			expectError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.desc == "successful client creation with TLS" {
				generateAndWriteCertificates(t, tc.caPath, tc.certPath, tc.keyPath)

				defer func() {
					os.Remove(tc.certPath)
					os.Remove(tc.keyPath)
					os.Remove(tc.caPath)
				}()
			} else if tc.desc == "failed client creation with invalid cert" {
				writeFile(t, tc.certPath, []byte("invalid cert content"))
				writeFile(t, tc.keyPath, []byte("invalid key content"))
				writeFile(t, tc.caPath, []byte("invalid ca content"))

				defer func() {
					os.Remove(tc.certPath)
					os.Remove(tc.keyPath)
					os.Remove(tc.caPath)
				}()
			}

			client, err := callback.NewCalloutClient(tc.ctls, tc.certPath, tc.keyPath, tc.caPath, tc.timeout)
			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func generateAndWriteCertificates(t *testing.T, caPath, certPath, keyPath string) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate CA private key")

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err, "Failed to create CA certificate")

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate client private key")

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "Test Client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientBytes, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	require.NoError(t, err, "Failed to create client certificate")

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	writeFile(t, caPath, caPEM)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientBytes,
	})
	writeFile(t, certPath, certPEM)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})
	writeFile(t, keyPath, keyPEM)
}

func writeFile(t *testing.T, path string, content []byte) {
	err := os.WriteFile(path, content, filePermission)
	require.NoError(t, err, "Failed to write file: %s", path)
}

func TestCallback_MakeRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			assert.Equal(t, "test-value", r.URL.Query().Get("test-param"))
		} else if r.Method == http.MethodPost {
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client, err := callback.NewCalloutClient(false, "", "", "", time.Second)
	assert.NoError(t, err)

	cb, err := callback.NewCallback(client, http.MethodPost, []string{ts.URL}, []string{permission})
	assert.NoError(t, err)

	err = cb.Callback(context.Background(), pl)
	assert.NoError(t, err)
}

func TestCallback_MakeRequest_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	client, err := callback.NewCalloutClient(false, "", "", "", time.Second)
	assert.NoError(t, err)

	cb, err := callback.NewCallback(client, http.MethodPost, []string{ts.URL}, []string{permission})
	assert.NoError(t, err)

	err = cb.Callback(context.Background(), pl)
	assert.Error(t, err)
	assert.True(t, errors.Contains(err, svcerr.ErrAuthorization))
}

func TestCallback_MakeRequest_InvalidURL(t *testing.T) {
	client, err := callback.NewCalloutClient(false, "", "", "", time.Second)
	assert.NoError(t, err)

	cb, err := callback.NewCallback(client, http.MethodGet, []string{"http://invalid-url"}, []string{permission})
	assert.NoError(t, err)

	err = cb.Callback(context.Background(), pl)
	assert.Error(t, err)
}

func TestCallback_MakeRequest_CancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client, err := callback.NewCalloutClient(false, "", "", "", time.Second)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cb, err := callback.NewCallback(client, http.MethodGet, []string{ts.URL}, []string{permission})
	assert.NoError(t, err)

	err = cb.Callback(ctx, pl)
	assert.Error(t, err)
}
