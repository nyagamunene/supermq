// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/absmach/magistrala/pkg/errors"
)

type Page struct {
	Total   uint64
	Offset  uint64
	Limit   uint64
	Revoked string
}

var ErrMissingCerts = errors.New("CA path or CA key path not set")

func LoadCertificates(caPath, caKeyPath string) (tls.Certificate, *x509.Certificate, error) {
	if caPath == "" || caKeyPath == "" {
		return tls.Certificate{}, &x509.Certificate{}, ErrMissingCerts
	}

	_, err := os.Stat(caPath)
	if os.IsNotExist(err) || os.IsPermission(err) {
		return tls.Certificate{}, &x509.Certificate{}, err
	}

	_, err = os.Stat(caKeyPath)
	if os.IsNotExist(err) || os.IsPermission(err) {
		return tls.Certificate{}, &x509.Certificate{}, err
	}

	tlsCert, err := tls.LoadX509KeyPair(caPath, caKeyPath)
	if err != nil {
		return tlsCert, &x509.Certificate{}, err
	}

	b, err := os.ReadFile(caPath)
	if err != nil {
		return tlsCert, &x509.Certificate{}, err
	}

	caCert, err := ReadCert(b)
	if err != nil {
		return tlsCert, &x509.Certificate{}, err
	}

	return tlsCert, caCert, nil
}

func ReadCert(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM data")
	}

	return x509.ParseCertificate(block.Bytes)
}
