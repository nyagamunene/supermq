// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/auth"
	"github.com/absmach/magistrala/internal/testsutil"
	"github.com/absmach/magistrala/pkg/apiutil"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	grpcapi "github.com/absmach/magistrala/things/api/grpc"
	"github.com/absmach/magistrala/things/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

const port = 7070

var (
	thingID   = "testID"
	channelID = "testID"
	invalid   = "invalid"
	valid     = "valid"
)

var svc *mocks.Service

func startGRPCServer(svc *mocks.Service, port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		panic(fmt.Sprintf("failed to obtain port: %s", err))
	}
	server := grpc.NewServer()
	magistrala.RegisterAuthzServiceServer(server, grpcapi.NewServer(svc))
	go func() {
		if err := server.Serve(listener); err != nil {
			panic(fmt.Sprintf("failed to serve: %s", err))
		}
	}()
}

func TestMain(m *testing.M) {
	svc = new(mocks.Service)
	startGRPCServer(svc, port)

	code := m.Run()

	os.Exit(code)
}

func TestAuthorize(t *testing.T) {
	authAddr := fmt.Sprintf("localhost:%d", port)
	conn, _ := grpc.NewClient(authAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	client := grpcapi.NewClient(conn, time.Second)

	cases := []struct {
		desc         string
		authorizeReq *magistrala.AuthorizeReq
		res          *magistrala.AuthorizeRes
		thingID      string
		authorizeErr error
		err          error
		code         codes.Code
	}{
		{
			desc: "authorize successfully",
			authorizeReq: &magistrala.AuthorizeReq{
				Subject:     thingID,
				SubjectKind: auth.ThingsKind,
				Permission:  valid,
				SubjectType: auth.ThingType,
				Object:      channelID,
				ObjectType:  auth.GroupType,
			},
			thingID: thingID,
			res:     &magistrala.AuthorizeRes{Authorized: true, Id: thingID},
			err:     nil,
		},
		{
			desc: "authorize with invalid id",
			authorizeReq: &magistrala.AuthorizeReq{
				Subject:     invalid,
				SubjectKind: auth.ThingsKind,
				Permission:  "publish",
				SubjectType: auth.ThingType,
				Object:      channelID,
				ObjectType:  auth.GroupType,
			},
			res: &magistrala.AuthorizeRes{},
			err: svcerr.ErrAuthentication,
		},
		{
			desc: "authorize with missing ID",
			authorizeReq: &magistrala.AuthorizeReq{
				Subject:     "",
				SubjectKind: auth.ThingsKind,
				Permission:  valid,
				SubjectType: auth.ThingType,
				Object:      channelID,
				ObjectType:  auth.GroupType,
			},
			res: &magistrala.AuthorizeRes{},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "authorize with unauthorized id",
			authorizeReq: &magistrala.AuthorizeReq{
				Subject:     invalid,
				SubjectKind: auth.ThingsKind,
				Permission:  valid,
				SubjectType: auth.ThingType,
				Object:      channelID,
				ObjectType:  auth.GroupType,
			},
			res: &magistrala.AuthorizeRes{},
			err: svcerr.ErrAuthorization,
		},
		{
			desc: "authorize with invalid permission",
			authorizeReq: &magistrala.AuthorizeReq{
				Subject:     thingID,
				SubjectKind: auth.ThingsKind,
				Permission:  invalid,
				SubjectType: auth.ThingType,
				Object:      channelID,
				ObjectType:  auth.GroupType,
			},
			res: &magistrala.AuthorizeRes{},
			err: svcerr.ErrAuthorization,
		},
		{
			desc: "authorize with invalid channel ID",
			authorizeReq: &magistrala.AuthorizeReq{
				Subject:     thingID,
				SubjectKind: auth.ThingsKind,
				Permission:  valid,
				SubjectType: auth.ThingType,
				Object:      invalid,
				ObjectType:  auth.GroupType,
			},
			res: &magistrala.AuthorizeRes{},
			err: svcerr.ErrAuthorization,
		},
		{
			desc: "authorize with empty channel ID",
			authorizeReq: &magistrala.AuthorizeReq{
				Subject:     thingID,
				SubjectKind: auth.ThingsKind,
				Permission:  valid,
				SubjectType: auth.ThingType,
				Object:      "",
				ObjectType:  auth.GroupType,
			},
			res: &magistrala.AuthorizeRes{},
			err: svcerr.ErrAuthorization,
		},
		{
			desc: "authorize with empty permission",
			authorizeReq: &magistrala.AuthorizeReq{
				Subject:     thingID,
				SubjectKind: auth.ThingsKind,
				Permission:  "",
				SubjectType: auth.ThingType,
				Object:      channelID,
				ObjectType:  auth.GroupType,
			},
			res: &magistrala.AuthorizeRes{},
			err: svcerr.ErrAuthorization,
		},
	}

	for _, tc := range cases {
		svcCall := svc.On("Authorize", mock.Anything, tc.authorizeReq).Return(tc.thingID, tc.err)
		res, err := client.Authorize(context.Background(), tc.authorizeReq)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.res, res, fmt.Sprintf("%s: expected %s got %s", tc.desc, tc.res, res))
		svcCall.Unset()
	}
}

func TestVerifyConnections(t *testing.T) {
	authAddr := fmt.Sprintf("localhost:%d", port)
	conn, err := grpc.NewClient(authAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.Nil(t, err, fmt.Sprintf("Unexpected error creating client connection %s", err))
	client := grpcapi.NewClient(conn, time.Second)

	thingsID := []string{testsutil.GenerateUUID(t)}
	channelsID := []string{testsutil.GenerateUUID(t)}
	cases := []struct {
		desc                 string
		verifyConnectionsReq *magistrala.VerifyConnectionsReq
		verifyConnectionsRes *magistrala.VerifyConnectionsRes
		err                  error
	}{
		{
			desc: "verify valid connection",
			verifyConnectionsReq: &magistrala.VerifyConnectionsReq{
				ThingsId: thingsID,
				GroupsId: channelsID,
			},
			verifyConnectionsRes: &magistrala.VerifyConnectionsRes{
				Status: mgclients.AllConnected,
				Connections: []*magistrala.Connectionstatus{
					{
						ThingId:   thingsID[0],
						ChannelId: channelsID[0],
						Status:    int32(mgclients.Connected),
					},
				},
			},
			err: nil,
		},
		{
			desc: "verify with invalid thing id",
			verifyConnectionsReq: &magistrala.VerifyConnectionsReq{
				ThingsId: []string{"invalid"},
				GroupsId: channelsID,
			},
			verifyConnectionsRes: &magistrala.VerifyConnectionsRes{},
			err:                  svcerr.ErrMalformedEntity,
		},
	}
	for _, tc := range cases {
		svcCall := svc.On("VerifyConnections", mock.Anything, mock.Anything, mock.Anything).Return(tc.verifyConnectionsRes, tc.err)
		vc, err := client.VerifyConnections(context.Background(), tc.verifyConnectionsReq)
		assert.Equal(t, tc.verifyConnectionsRes.GetConnections(), vc.GetConnections(), fmt.Sprintf("%s: expected %v got %v", tc.desc, tc.verifyConnectionsRes.GetConnections(), vc.GetConnections()))
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		svcCall.Unset()
	}
}
