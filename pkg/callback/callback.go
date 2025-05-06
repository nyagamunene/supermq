// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package callback

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

const (
	CreatePerm = "create.permission"
	DeletePerm = "delete.permission"
)

var errLimitExceeded = errors.New("limit exceeded")

type Config struct {
	AuthCalloutURLs            []string      `env:"SMQ_AUTH_CALLOUT_URLS"             envDefault:"" envSeparator:","`
	AuthCalloutMethod          string        `env:"SMQ_AUTH_CALLOUT_METHOD"           envDefault:"POST"`
	AuthCalloutTLSVerification bool          `env:"SMQ_AUTH_CALLOUT_TLS_VERIFICATION" envDefault:"true"`
	AuthCalloutTimeout         time.Duration `env:"SMQ_AUTH_CALLOUT_TIMEOUT"          envDefault:"10s"`
	AuthCalloutCACert          string        `env:"SMQ_AUTH_CALLOUT_CA_CERT"          envDefault:""`
	AuthCalloutCert            string        `env:"SMQ_AUTH_CALLOUT_CERT"             envDefault:""`
	AuthCalloutKey             string        `env:"SMQ_AUTH_CALLOUT_KEY"              envDefault:""`
	AuthCalloutPermissions     []string      `env:"SMQ_AUTH_CALLOUT_INVOKE_PERMISSIONS" envDefault:"" envSeparator:","`
}

type callback struct {
	httpClient        *http.Client
	urls              []string
	method            string
	allowedPermission map[string]struct{}
}

// CallBack send auth request to an external service.
type CallBack interface {
	Callback(ctx context.Context, pl map[string]interface{}) error
}

// NewCallback creates a new instance of CallBack.
func NewCallback(httpClient *http.Client, method string, urls []string, permissions []string) (CallBack, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if method != http.MethodPost && method != http.MethodGet {
		return nil, fmt.Errorf("unsupported auth callback method: %s", method)
	}

	allowedPermission := make(map[string]struct{})
	for _, permission := range permissions {
		allowedPermission[permission] = struct{}{}
	}

	return &callback{
		httpClient:        httpClient,
		urls:              urls,
		method:            method,
		allowedPermission: allowedPermission,
	}, nil
}

func NewCalloutClient(ctls bool, certPath, keyPath, caPath string, timeout time.Duration) (*http.Client, error) {
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

func (c *callback) makeRequest(ctx context.Context, urlStr string, params map[string]string) error {
	var req *http.Request
	var err error

	switch c.method {
	case http.MethodGet:
		query := url.Values{}
		for key, value := range params {
			query.Set(key, value)
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

func (c *callback) Callback(ctx context.Context, pl map[string]interface{}) error {
	if len(c.urls) == 0 {
		return nil
	}

	// Check if the permission is in the allowed list
	// Otherwise, only call webhook if the permission is in the map
	if len(c.allowedPermission) > 0 {
		val, ok := pl["permission"].(string)
		if ok {
			_, exists := c.allowedPermission[val]
			if !exists {
				return nil
			}
		}
	}

	payload := map[string]string{
		"domain":      pl["domain"].(string),
		"sender":      pl["sender"].(string),
		"entity_type": pl["entity_type"].(string),
		"time":        pl["time"].(string),
		"permission":  pl["permission"].(string),
	}

	var err error
	// We iterate through all URLs in sequence
	// if any request fails, we return the error immediately
	for _, url := range c.urls {
		if err = c.makeRequest(ctx, url, payload); err != nil {
			return errors.Wrap(errLimitExceeded, err)
		}
	}

	return nil
}
