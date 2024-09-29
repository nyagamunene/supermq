// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
package sdk

import (
	"github.com/absmach/certs/sdk"
	"golang.org/x/crypto/ocsp"
)

type Agent interface {
	Issue(entityId, ttl string, ipAddrs []string) (sdk.Certificate, error)

	Download(serialNumber string) (sdk.CertificateBundle, error)

	View(serialNumber string) (sdk.Certificate, error)

	Revoke(serialNumber string) error

	Renew(serialNumber string) error

	GetDownloadToken(serialNumber string) (sdk.Token, error)

	ListCerts(pm sdk.PageMetadata) (sdk.CertificatePage, error)

	OCSP(serialNumber string) (ocsp.Response, error)
}

type sdkAgent struct {
	sdk sdk.SDK
}

func NewAgent(host, certsURL string, TLSVerification bool) (Agent, error) {
	msgContentType := string(sdk.CTJSONSenML)
	certConfig := sdk.Config{
		CertsURL:        certsURL,
		HostURL:         host,
		MsgContentType:  sdk.ContentType(msgContentType),
		TLSVerification: TLSVerification,
	}

	return sdkAgent{
		sdk: sdk.NewSDK(certConfig),
	}, nil
}

func (c sdkAgent) Issue(entityId, ttl string, ipAddrs []string) (sdk.Certificate, error) {
	cert, err := c.sdk.IssueCert(entityId, ttl, ipAddrs, sdk.Options{CommonName: "Magistrala"})
	if err != nil {
		return sdk.Certificate{}, err
	}

	return cert, nil
}

func (c sdkAgent) Download(serial string) (sdk.CertificateBundle, error) {
	downloadToken, err := c.sdk.RetrieveCertDownloadToken(serial)
	if err != nil {
		return sdk.CertificateBundle{}, err
	}

	bundle, err := c.sdk.DownloadCert(downloadToken.Token, serial)
	if err != nil {
		return sdk.CertificateBundle{}, err
	}

	return bundle, nil
}

func (c sdkAgent) View(serial string) (sdk.Certificate, error) {
	cert, err := c.sdk.ViewCert(serial)
	if err != nil {
		return sdk.Certificate{}, err
	}
	return cert, nil
}

func (c sdkAgent) Revoke(serial string) error {
	if err := c.sdk.RevokeCert(serial); err != nil {
		return err
	}

	return nil
}

func (c sdkAgent) Renew(serial string) error {
	if err := c.sdk.RenewCert(serial); err != nil {
		return err
	}
	return nil
}

func (c sdkAgent) GetDownloadToken(serial string) (sdk.Token, error) {
	downloadToken, err := c.sdk.RetrieveCertDownloadToken(serial)
	if err != nil {
		return sdk.Token{}, err
	}

	return downloadToken, nil
}

func (c sdkAgent) ListCerts(pm sdk.PageMetadata) (sdk.CertificatePage, error) {
	certPage, err := c.sdk.ListCerts(pm)
	if err != nil {
		return sdk.CertificatePage{}, err
	}
	return certPage, nil
}

func (c sdkAgent) OCSP(serial string) (ocsp.Response, error) {
	response, err := c.sdk.OCSP(serial)
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
