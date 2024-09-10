// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package certs

import (
	"context"
	"time"

	"github.com/absmach/certs/sdk"
	"github.com/absmach/magistrala"
	pki "github.com/absmach/magistrala/certs/pki/am-certs"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	mgsdk "github.com/absmach/magistrala/pkg/sdk/go"
)

var (
	// ErrFailedCertCreation failed to create certificate.
	ErrFailedCertCreation = errors.New("failed to create client certificate")

	// ErrFailedCertRevocation failed to revoke certificate.
	ErrFailedCertRevocation = errors.New("failed to revoke certificate")

	ErrFailedToRemoveCertFromDB = errors.New("failed to remove cert serial from db")

	ErrFailedReadFromPKI = errors.New("failed to read certificate from PKI")
)

var _ Service = (*certsService)(nil)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
//
//go:generate mockery --name Service --output=./mocks --filename service.go --quiet --note "Copyright (c) Abstract Machines"
type Service interface {
	// IssueCert issues certificate for given thing id if access is granted with token
	IssueCert(ctx context.Context, token, thingID, ttl string) (sdk.SerialNumber, error)

	// ListCerts lists certificates issued for a given thing ID
	ListCerts(ctx context.Context, token, thingID string, offset, limit uint64) (sdk.CertificatePage, error)

	// ListSerials lists certificate serial IDs issued for a given thing ID
	ListSerials(ctx context.Context, token, thingID string, offset, limit uint64) (sdk.CertificatePage, error)

	// ViewCert retrieves the certificate issued for a given serial ID
	ViewCert(ctx context.Context, token, serialID string) (sdk.Certificate, error)

	// RevokeCert revokes a certificate for a given thing ID
	RevokeCert(ctx context.Context, token, thingID string) (Revoke, error)
}

type certsService struct {
	auth magistrala.AuthnServiceClient
	sdk  mgsdk.SDK
	pki  pki.Agent
}

// New returns new Certs service.
func New(auth magistrala.AuthnServiceClient, sdk mgsdk.SDK, pkiAgent pki.Agent) Service {
	return &certsService{
		sdk:  sdk,
		auth: auth,
		pki:  pkiAgent,
	}
}

// Revoke defines the conditions to revoke a certificate.
type Revoke struct {
	RevocationTime time.Time `mapstructure:"revocation_time"`
}

// Cert defines the certificate paremeters.
type Cert struct {
	OwnerID        string    `json:"owner_id" mapstructure:"owner_id"`
	ThingID        string    `json:"thing_id" mapstructure:"thing_id"`
	ClientCert     string    `json:"client_cert" mapstructure:"certificate"`
	IssuingCA      string    `json:"issuing_ca" mapstructure:"issuing_ca"`
	CAChain        []string  `json:"ca_chain" mapstructure:"ca_chain"`
	ClientKey      string    `json:"client_key" mapstructure:"private_key"`
	PrivateKeyType string    `json:"private_key_type" mapstructure:"private_key_type"`
	Serial         string    `json:"serial" mapstructure:"serial_number"`
	Expire         time.Time `json:"expire" mapstructure:"-"`
}

func (cs *certsService) IssueCert(ctx context.Context, token, thingID, ttl string) (sdk.SerialNumber, error) {
	_, err := cs.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return sdk.SerialNumber{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	thing, err := cs.sdk.Thing(thingID, token)
	if err != nil {
		return sdk.SerialNumber{}, errors.Wrap(ErrFailedCertCreation, err)
	}

	SerialNumber, err := cs.pki.Issue(thing.Credentials.Secret, []string{})
	if err != nil {
		return sdk.SerialNumber{}, errors.Wrap(ErrFailedCertCreation, err)
	}

	return SerialNumber, err
}

func (cs *certsService) RevokeCert(ctx context.Context, token, thingID string) (Revoke, error) {
	var revoke Revoke
	_, err := cs.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return revoke, errors.Wrap(svcerr.ErrAuthentication, err)
	}
	thing, err := cs.sdk.Thing(thingID, token)
	if err != nil {
		return revoke, errors.Wrap(ErrFailedCertRevocation, err)
	}

	cp, err := cs.pki.ListCerts(sdk.PageMetadata{Offset: 0, Limit: 10000, EntityID: thing.ID})
	if err != nil {
		return revoke, errors.Wrap(ErrFailedCertRevocation, err)
	}

	for _, c := range cp.Certificates {
		err := cs.pki.Revoke(c.SerialNumber)
		if err != nil {
			return revoke, errors.Wrap(ErrFailedCertRevocation, err)
		}
		revoke.RevocationTime = time.Now()
	}

	return revoke, nil
}

func (cs *certsService) ListCerts(ctx context.Context, token, thingID string, offset, limit uint64) (sdk.CertificatePage, error) {
	_, err := cs.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return sdk.CertificatePage{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	cp, err := cs.pki.ListCerts(sdk.PageMetadata{Offset: offset, Limit: limit, EntityID: thingID})
	if err != nil {
		return sdk.CertificatePage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return cp, nil
}

func (cs *certsService) ListSerials(ctx context.Context, token, thingID string, offset, limit uint64) (sdk.CertificatePage, error) {
	_, err := cs.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return sdk.CertificatePage{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	cp, err := cs.pki.ListCerts(sdk.PageMetadata{Offset: offset, Limit: limit, EntityID: thingID})
	if err != nil {
		return sdk.CertificatePage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	var certs []sdk.Certificate
	for _, c := range cp.Certificates {
		certs = append(certs, sdk.Certificate{SerialNumber: c.SerialNumber})
	}
	return sdk.CertificatePage{
		Offset:       cp.Offset,
		Limit:        cp.Limit,
		Total:        cp.Total,
		Certificates: certs}, nil
}

func (cs *certsService) ViewCert(ctx context.Context, token, serialID string) (sdk.Certificate, error) {
	_, err := cs.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return sdk.Certificate{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	// cert, err := cs.certsRepo.RetrieveBySerial(ctx, u.GetId(), serialID)
	// if err != nil {
	// 	return Cert{}, errors.Wrap(svcerr.ErrViewEntity, err)
	// }

	bytes, err := cs.pki.Retrieve(serialID)
	if err != nil {
		return sdk.Certificate{}, errors.Wrap(ErrFailedReadFromPKI, err)
	}

	cert, err := ReadCert(bytes)
	if err != nil {
		return sdk.Certificate{}, errors.Wrap(ErrFailedReadFromPKI, err)
	}

	return sdk.Certificate{
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}
