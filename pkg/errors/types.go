// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package errors


var (
	// ErrMalformedEntity indicates a malformed entity specification.
	ErrMalformedEntity = New("malformed entity specification")

	// ErrUnsupportedContentType indicates invalid content type.
	ErrUnsupportedContentType = New("invalid content type")

	// ErrUnidentified indicates unidentified error.
	ErrUnidentified = New("unidentified error")

	// ErrEmptyPath indicates empty file path.
	ErrEmptyPath = New("empty file path")

	// ErrStatusAlreadyAssigned indicated that the client or group has already been assigned the status.
	ErrStatusAlreadyAssigned = New("status already assigned")

	// ErrRollbackTx indicates failed to rollback transaction.
	ErrRollbackTx = New("failed to rollback transaction")
)
