// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
package pki

import (
	"fmt"

	"github.com/absmach/certs/sdk"
	"golang.org/x/crypto/ocsp"
)

type Agent interface {
	Issue(entityId string, ipAddrs []string) (sdk.SerialNumber, error)

	Download(serialNumber string) ([]byte, error)

	View(serialNumber string) (sdk.Certificate, error)

	Revoke(serialNumber string) error

	Renew(serialNumber string) error

	GetDownloadToken(serialNumber string) (sdk.Token, error)

	ListCerts(pm sdk.PageMetadata) (sdk.CertificatePage, error)

	OCSP(serialNumber string) (ocsp.Response, error)
}

type pkiAgent struct {
	pki sdk.SDK
}

func NewAgent(Host, CertsURL string, TLSVerification bool) (Agent, error) {
	certConfig := sdk.Config{
		CertsURL:        CertsURL,
		HostURL:         Host,
		MsgContentType:  sdk.CTJSON,
		TLSVerification: TLSVerification,
	}

	c := &pkiAgent{
		pki: sdk.NewSDK(certConfig),
	}

	return c, nil
}

func (c pkiAgent) Issue(entityId string, ipAddrs []string) (sdk.SerialNumber, error) {
	serial, err := c.pki.IssueCert(entityId, ipAddrs)
	if err != nil {
		return sdk.SerialNumber{}, err
	}

	return serial, nil
}

func (c pkiAgent) Download(serial string) ([]byte, error) {
	downloadToken, err := c.pki.RetrieveCertDownloadToken(serial)
	if err != nil {
		return []byte{}, err
	}

	bytes, err := c.pki.DownloadCert(downloadToken.Token, serial)
	if err != nil {
		return []byte{}, err
	}

	return bytes, nil
}

func (c pkiAgent) View(serial string) (sdk.Certificate, error) {
	cert, err := c.pki.ViewCert(serial)
	if err != nil {
		return sdk.Certificate{}, err
	}
	return cert, nil
}

func (c pkiAgent) Revoke(serial string) error {
	if err := c.pki.RevokeCert(serial); err != nil {
		return err
	}

	return nil
}

func (c pkiAgent) Renew(serial string) error {
	if err := c.pki.RenewCert(serial); err != nil {
		return err
	}
	return nil
}

func (c pkiAgent) GetDownloadToken(serial string) (sdk.Token, error) {
	downloadToken, err := c.pki.RetrieveCertDownloadToken(serial)
	if err != nil {
		return sdk.Token{}, err
	}

	return downloadToken, nil
}

func (c pkiAgent) ListCerts(pm sdk.PageMetadata) (sdk.CertificatePage, error) {
	certPage, err := c.pki.ListCerts(pm)
	if err != nil {
		return sdk.CertificatePage{}, err
	}

	return certPage, nil
}

func (c pkiAgent) OCSP(serial string) (ocsp.Response, error) {
	response, err := c.pki.OCSP(serial)
	if err != nil {
		return ocsp.Response{}, err
	}

	ocspRes := ocsp.Response{
		Raw:                response.Raw,
		Status:             response.Status,
		SerialNumber:       response.SerialNumber,
		ProducedAt:         response.ProducedAt,
		ThisUpdate:         response.ThisUpdate,
		NextUpdate:         response.NextUpdate,
		RevokedAt:          response.RevokedAt,
		RevocationReason:   response.RevocationReason,
		Certificate:        response.Certificate,
		TBSResponseData:    response.TBSResponseData,
		Signature:          response.Signature,
		SignatureAlgorithm: response.SignatureAlgorithm,
		IssuerHash:         response.IssuerHash,
		RawResponderName:   response.RawResponderName,
		ResponderKeyHash:   response.ResponderKeyHash,
		Extensions:         response.Extensions,
		ExtraExtensions:    response.ExtraExtensions,
	}

	return ocspRes, nil
}
