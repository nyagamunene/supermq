// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package callout

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
)

var errLimitExceeded = errors.New("limit exceeded")

type Config struct {
	CalloutURLs            []string      `env:"URLS"             envDefault:"" envSeparator:","`
	CalloutMethod          string        `env:"METHOD"           envDefault:"POST"`
	CalloutTLSVerification bool          `env:"TLS_VERIFICATION" envDefault:"true"`
	CalloutTimeout         time.Duration `env:"TIMEOUT"          envDefault:"10s"`
	CalloutCACert          string        `env:"CA_CERT"          envDefault:""`
	CalloutCert            string        `env:"CERT"             envDefault:""`
	CalloutKey             string        `env:"KEY"              envDefault:""`
	CalloutPermissions     []string      `env:"INVOKE_PERMISSIONS" envDefault:"" envSeparator:","`
}

type callout struct {
	httpClient        *http.Client
	urls              []string
	method            string
	allowedPermission map[string]struct{}
}

// Callout send request to an external service.
type Callout interface {
	Callout(ctx context.Context, perm string, pl map[string]interface{}) error
}

// NewCallback creates a new instance of Callout.
func NewCallout(ctls bool, certPath, keyPath, caPath string, timeout time.Duration, method string, urls []string, permissions []string) (Callout, error) {
	httpClient, err := newCalloutClient(ctls, certPath, keyPath, caPath, timeout)
	if err != nil {
		return nil, fmt.Errorf("failied to initialize http client: %w", err)
	}

	if method != http.MethodPost && method != http.MethodGet {
		return nil, fmt.Errorf("unsupported auth callout method: %s", method)
	}

	allowedPermission := make(map[string]struct{})
	for _, permission := range permissions {
		allowedPermission[permission] = struct{}{}
	}

	return &callout{
		httpClient:        httpClient,
		urls:              urls,
		method:            method,
		allowedPermission: allowedPermission,
	}, nil
}

func newCalloutClient(ctls bool, certPath, keyPath, caPath string, timeout time.Duration) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !ctls,
	}
	if certPath != "" || keyPath != "" {
		clientTLSCert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, errors.Wrap(errors.New("failed to append CA certificate"), svcerr.ErrCreateEntity)
		}
		tlsConfig.RootCAs = certPool
		tlsConfig.Certificates = []tls.Certificate{clientTLSCert}
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: timeout,
	}

	return httpClient, nil
}

func (c *callout) makeRequest(ctx context.Context, urlStr string, params map[string]interface{}) error {
	var req *http.Request
	var err error

	switch c.method {
	case http.MethodGet:
		query := url.Values{}
		for key, value := range params {
			if v, ok := value.(string); ok {
				query.Set(key, v)
			}
		}
		req, err = http.NewRequestWithContext(ctx, c.method, urlStr+"?"+query.Encode(), nil)
	case http.MethodPost:
		data, jsonErr := json.Marshal(params)
		if jsonErr != nil {
			return jsonErr
		}
		req, err = http.NewRequestWithContext(ctx, c.method, urlStr, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
	}

	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, resp.StatusCode)
	}

	return nil
}

func (c *callout) Callout(ctx context.Context, op string, pl map[string]interface{}) error {
	if len(c.urls) == 0 {
		return nil
	}

	// Check if the permission is in the allowed list
	// Otherwise, only call webhook if the permission is in the map
	if len(c.allowedPermission) > 0 {
		_, exists := c.allowedPermission[op]
		if !exists {
			return nil
		}
	}
	pl["permission"] = op

	var err error
	// We iterate through all URLs in sequence
	// if any request fails, we return the error immediately
	for _, url := range c.urls {
		if err = c.makeRequest(ctx, url, pl); err != nil {
			return errors.Wrap(errLimitExceeded, err)
		}
	}

	return nil
}
