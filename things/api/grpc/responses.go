// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

type authorizeRes struct {
	id         string
	authorized bool
}

type verifyConnectionsRes struct {
	Status      string
	Connections []ConnectionStatus
}

type ConnectionStatus struct {
	ThingId   string
	ChannelId string
	Status    string
}
