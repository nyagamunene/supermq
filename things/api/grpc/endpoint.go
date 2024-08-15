// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/things"
	"github.com/go-kit/kit/endpoint"
)

func authorizeEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*magistrala.AuthorizeReq)

		id, err := svc.Authorize(ctx, req)
		if err != nil {
			return authorizeRes{}, err
		}
		return authorizeRes{
			authorized: true,
			id:         id,
		}, err
	}
}

func verifyConnectionsEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(*magistrala.VerifyConnectionsReq)

		conns, err := svc.VerifyConnections(ctx, req.GetThingIds(), req.GetGroupIds())
		if err != nil {
			return verifyConnectionsRes{}, err
		}
		cs := []connectionStatus{}
		for _, c := range conns.Connections {
			cs = append(cs, connectionStatus{
				ThingId:   c.ThingId,
				ChannelId: c.ChannelId,
				Status:    c.Status.String(),
			})
		}
		return verifyConnectionsRes{Status: conns.Status.String(), Connections: cs}, nil
	}
}
