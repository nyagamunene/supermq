// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"

	grpcAuthV1 "github.com/absmach/supermq/api/grpc/auth/v1"
	"github.com/absmach/supermq/auth"
	grpcapi "github.com/absmach/supermq/auth/api/grpc"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
)

var _ grpcAuthV1.AuthServiceServer = (*authGrpcServer)(nil)

type authGrpcServer struct {
	grpcAuthV1.UnimplementedAuthServiceServer
	authorize    kitgrpc.Handler
	authenticate kitgrpc.Handler
}

// NewAuthServer returns new AuthnServiceServer instance.
func NewAuthServer(svc auth.Service) grpcAuthV1.AuthServiceServer {
	return &authGrpcServer{
		authorize: kitgrpc.NewServer(
			(authorizeEndpoint(svc)),
			decodeAuthorizeRequest,
			encodeAuthorizeResponse,
		),

		authenticate: kitgrpc.NewServer(
			(authenticateEndpoint(svc)),
			decodeAuthenticateRequest,
			encodeAuthenticateResponse,
		),
	}
}

func (s *authGrpcServer) Authenticate(ctx context.Context, req *grpcAuthV1.AuthNReq) (*grpcAuthV1.AuthNRes, error) {
	_, res, err := s.authenticate.ServeGRPC(ctx, req)
	if err != nil {
		return nil, grpcapi.EncodeError(err)
	}
	return res.(*grpcAuthV1.AuthNRes), nil
}

func (s *authGrpcServer) Authorize(ctx context.Context, req *grpcAuthV1.AuthZReq) (*grpcAuthV1.AuthZRes, error) {
	_, res, err := s.authorize.ServeGRPC(ctx, req)
	if err != nil {
		return nil, grpcapi.EncodeError(err)
	}
	return res.(*grpcAuthV1.AuthZRes), nil
}

func decodeAuthenticateRequest(_ context.Context, grpcReq any) (any, error) {
	req := grpcReq.(*grpcAuthV1.AuthNReq)
	return authenticateReq{token: req.GetToken()}, nil
}

func encodeAuthenticateResponse(_ context.Context, grpcRes any) (any, error) {
	res := grpcRes.(authenticateRes)
	return &grpcAuthV1.AuthNRes{Id: res.id, UserId: res.userID, UserRole: uint32(res.userRole), Verified: res.verified, TokenType: res.tokenType}, nil
}

func decodeAuthorizeRequest(_ context.Context, grpcReq any) (any, error) {
	req := grpcReq.(*grpcAuthV1.AuthZReq)
	policy := req.GetPolicy()
	if policy == nil {
		return authReq{}, nil
	}

	if policy.GetPatId() != "" {
		return authReq{
			TokenType:  req.GetTokenType(),
			UserID:     policy.GetUserId(),
			PatID:      policy.GetPatId(),
			EntityType: auth.EntityType(policy.GetEntityType()),
			DomainID:   policy.GetDomain(),
			Operation:  auth.Operation(policy.GetOperation()),
			EntityID:   policy.GetEntityId(),
		}, nil
	}

	return authReq{
		TokenType:   req.GetTokenType(),
		Domain:      policy.GetDomain(),
		SubjectType: policy.GetSubjectType(),
		SubjectKind: policy.GetSubjectKind(),
		Subject:     policy.GetSubject(),
		Relation:    policy.GetRelation(),
		Permission:  policy.GetPermission(),
		ObjectType:  policy.GetObjectType(),
		Object:      policy.GetObject(),
	}, nil
}

func encodeAuthorizeResponse(_ context.Context, grpcRes any) (any, error) {
	res := grpcRes.(authorizeRes)
	return &grpcAuthV1.AuthZRes{Authorized: res.authorized, Id: res.id}, nil
}
