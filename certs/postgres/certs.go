// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/absmach/supermq/certs"
	"github.com/absmach/supermq/pkg/errors"
	repoerr "github.com/absmach/supermq/pkg/errors/repository"
	"github.com/absmach/supermq/pkg/postgres"
)

var _ certs.Repository = (*certsRepository)(nil)

type certsRepository struct {
	db postgres.Database
}

// NewRepository instantiates a PostgreSQL implementation of certs
// repository.
func NewRepository(db postgres.Database) certs.Repository {
	return &certsRepository{db: db}
}

func (cr certsRepository) RetrieveAll(ctx context.Context, offset, limit uint64) (certs.CertPage, error) {
	q := `SELECT client_id, serial_number, expiry_time FROM certs ORDER BY expiry_time LIMIT $1 OFFSET $2;`
	rows, err := cr.db.QueryContext(ctx, q, limit, offset)
	if err != nil {
		return certs.CertPage{}, err
	}
	defer rows.Close()

	certificates := []certs.Cert{}
	for rows.Next() {
		c := certs.Cert{}
		if err := rows.Scan(&c.ClientID, &c.SerialNumber, &c.ExpiryTime); err != nil {
			return certs.CertPage{}, err
		}
		certificates = append(certificates, c)
	}

	q = `SELECT COUNT(*) FROM certs`
	var total uint64
	if err := cr.db.QueryRowxContext(ctx, q).Scan(&total); err != nil {
		return certs.CertPage{}, err
	}

	return certs.CertPage{
		Total:        total,
		Limit:        limit,
		Offset:       offset,
		Certificates: certificates,
	}, nil
}

func (cr certsRepository) Save(ctx context.Context, cert certs.Cert) (string, error) {
	dbcrt := toDBCert(cert)

	q := `INSERT INTO certs (client_id, serial_number, expiry_time) 
	VALUES (:client_id, :serial_number, :expiry_time)
	RETURNING serial_number`

	row, err := cr.db.NamedQueryContext(ctx, q, dbcrt)
	if err != nil {
		return "", postgres.HandleError(repoerr.ErrCreateEntity, err)
	}
	defer row.Close()

	var serialNumber string
	if row.Next() {
		if err := row.Scan(&serialNumber); err != nil {
			return "", errors.Wrap(repoerr.ErrFailedOpDB, err)
		}
	}

	return serialNumber, nil
}

func (cr certsRepository) Remove(ctx context.Context, clientID string) error {
	q := `DELETE FROM certs WHERE client_id = :client_id`
	var c certs.Cert
	c.ClientID = clientID
	dbcrt := toDBCert(c)
	if _, err := cr.db.NamedExecContext(ctx, q, dbcrt); err != nil {
		return errors.Wrap(repoerr.ErrRemoveEntity, err)
	}
	return nil
}

func (cr certsRepository) RemoveBySerial(ctx context.Context, serialID string) error {
	q := `DELETE FROM certs WHERE serial_number = :serial_number`
	var c certs.Cert
	c.SerialNumber = serialID
	dbcrt := toDBCert(c)
	if _, err := cr.db.NamedExecContext(ctx, q, dbcrt); err != nil {
		return errors.Wrap(repoerr.ErrRemoveEntity, err)
	}
	return nil
}

func (cr certsRepository) RetrieveByClient(ctx context.Context, clientID string, offset, limit uint64) (certs.CertPage, error) {
	q := `SELECT client_id, serial_number, expiry_time FROM certs WHERE client_id = $1 ORDER BY expiry_time LIMIT $2 OFFSET $3;`
	rows, err := cr.db.QueryContext(ctx, q, clientID, limit, offset)
	if err != nil {
		return certs.CertPage{}, err
	}
	defer rows.Close()

	certificates := []certs.Cert{}
	for rows.Next() {
		c := certs.Cert{}
		if err := rows.Scan(&c.ClientID, &c.SerialNumber, &c.ExpiryTime); err != nil {
			return certs.CertPage{}, err
		}
		certificates = append(certificates, c)
	}

	q = `SELECT COUNT(*) FROM certs WHERE client_id = $1`
	var total uint64
	if err := cr.db.QueryRowxContext(ctx, q, clientID).Scan(&total); err != nil {
		return certs.CertPage{}, err
	}

	return certs.CertPage{
		Total:        total,
		Limit:        limit,
		Offset:       offset,
		Certificates: certificates,
	}, nil
}

func (cr certsRepository) RetrieveBySerial(ctx context.Context, serial string) (certs.Cert, error) {
	q := `SELECT client_id, serial_number, expiry_time FROM certs WHERE serial_number = $1`
	var dbcrt dbCert
	var c certs.Cert

	if err := cr.db.QueryRowxContext(ctx, q, serial).StructScan(&dbcrt); err != nil {
		if err == sql.ErrNoRows {
			return c, errors.Wrap(repoerr.ErrNotFound, err)
		}

		return c, errors.Wrap(repoerr.ErrViewEntity, err)
	}
	c = toCert(dbcrt)

	return c, nil
}

type dbCert struct {
	ClientID     string    `db:"client_id"`
	SerialNumber string    `db:"serial_number"`
	ExpiryTime   time.Time `db:"expiry_time"`
}

func toDBCert(c certs.Cert) dbCert {
	return dbCert{
		ClientID:     c.ClientID,
		SerialNumber: c.SerialNumber,
		ExpiryTime:   c.ExpiryTime,
	}
}

func toCert(cdb dbCert) certs.Cert {
	var c certs.Cert
	c.ClientID = cdb.ClientID
	c.SerialNumber = cdb.SerialNumber
	c.ExpiryTime = cdb.ExpiryTime
	return c
}
