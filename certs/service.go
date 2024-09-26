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

type PageMetadata struct {
	Offset uint64
	Limit  uint64
	Revoke string
}

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
//
//go:generate mockery --name Service --output=./mocks --filename service.go --quiet --note "Copyright (c) Abstract Machines"
type Service interface {
	// IssueCert issues certificate for given thing id if access is granted with token
	IssueCert(ctx context.Context, token, thingID, ttl string) (sdk.SerialNumber, error)

	// ListCerts lists certificates issued for a given thing ID
	ListCerts(ctx context.Context, token, thingID string, pm PageMetadata) (sdk.CertificatePage, error)

	// ListSerials lists certificate serial IDs issued for a given thing ID
	ListSerials(ctx context.Context, token, thingID string, pm PageMetadata) (sdk.CertificatePage, error)

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

func (cs *certsService) IssueCert(ctx context.Context, token, thingID, ttl string) (sdk.SerialNumber, error) {
	_, err := cs.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return sdk.SerialNumber{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	thing, err := cs.sdk.Thing(thingID, token)
	if err != nil {
		return sdk.SerialNumber{}, errors.Wrap(ErrFailedCertCreation, err)
	}

	SerialNumber, err := cs.pki.Issue(thing.ID, ttl, []string{})
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

func (cs *certsService) ListCerts(ctx context.Context, token, thingID string, pm PageMetadata) (sdk.CertificatePage, error) {
	_, err := cs.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return sdk.CertificatePage{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	cp, err := cs.pki.ListCerts(sdk.PageMetadata{Offset: pm.Offset, Limit: pm.Limit, EntityID: thingID})
	if err != nil {
		return sdk.CertificatePage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return cp, nil
}

func (cs *certsService) ListSerials(ctx context.Context, token, thingID string, pm PageMetadata) (sdk.CertificatePage, error) {
	_, err := cs.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return sdk.CertificatePage{}, errors.Wrap(svcerr.ErrAuthentication, err)
	}

	cp, err := cs.pki.ListCerts(sdk.PageMetadata{Offset: pm.Offset, Limit: pm.Limit, EntityID: thingID})
	if err != nil {
		return sdk.CertificatePage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	var certs []sdk.Certificate
	switch pm.Revoke {
	case "true":
		for _, c := range cp.Certificates {
			if c.Revoked {
				certs = append(certs, sdk.Certificate{
					SerialNumber: c.SerialNumber,
					EntityID:     c.EntityID,
					ExpiryTime:   c.ExpiryTime,
					Revoked:      c.Revoked,
				})
			}
		}
	case "false":
		for _, c := range cp.Certificates {
			if !c.Revoked {
				certs = append(certs, sdk.Certificate{
					SerialNumber: c.SerialNumber,
					EntityID:     c.EntityID,
					ExpiryTime:   c.ExpiryTime,
					Revoked:      c.Revoked,
				})
			}
		}
	case "all":
		for _, c := range cp.Certificates {
			certs = append(certs, sdk.Certificate{
				SerialNumber: c.SerialNumber,
				EntityID:     c.EntityID,
				ExpiryTime:   c.ExpiryTime,
				Revoked:      c.Revoked,
			})
		}
	}

	return sdk.CertificatePage{
		Offset:       cp.Offset,
		Limit:        cp.Limit,
		Total:        uint64(len(certs)),
		Certificates: certs,
	}, nil
}

func (cs *certsService) ViewCert(ctx context.Context, token, serialID string) (sdk.Certificate, error) {
	_, err := cs.auth.Identify(ctx, &magistrala.IdentityReq{Token: token})
	if err != nil {
		return sdk.Certificate{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	cert, err := cs.pki.View(serialID)
	if err != nil {
		return sdk.Certificate{}, errors.Wrap(ErrFailedReadFromPKI, err)
	}

	return cert, nil
}
